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

//add hypov8 store some client info. for gamespy requests
typedef struct clientTemp2_s
{
	SOCKET_NET socknum;
	time_t timeout;				//forget client
	qboolean valid;				//good to go. decrypted ok
	int gsEncType;				//encryption type 0, 1 or 2 (0 is byte compressed, no excryption)
	char browser_type[64];		//gamespy, kingpin, quake2
	char decrypt_str[64];		//"mgNUaC"
	struct sockaddr_in tmpClientAddress ;
}clientTemp2_t;


clientTemp2_t clientinfo_tcp[MAX_CLIENTS];

// ---------- Public functions ---------- //

// Parse a packet to figure out what to do with it
void	MSG_HandleMessage_KP1(const char *msg, const struct sockaddr_in *address, SOCKET_NET recv_sock, int nb_bytes);
int		MSG_HandleMessage_GspyTCP(const char *msg, const struct sockaddr_in *address, int clientID);
void	MSG_HandleMessage_KPQ3(const char *msg, const struct sockaddr_in *address, SOCKET_NET recv_sock);

#endif							// _MESSAGES_H_
