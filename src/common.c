
#include "common.h"



static qboolean Com_isStringEOL(char c)
{
	if (c == '\0' ||  c == '/' ||isspace((unsigned char)c))
		return qtrue;
	return qfalse;
}

qboolean Com_isStringComment(char c)
{
	if (c == '\0' || c == '/' || c == '#' || c == '\\')
		return qtrue;
	return qfalse;
}


//handle a line/string from files containing an ip
qboolean Com_GetIpPortFromLine(char *in, char *outIP, char *outPort)
{
	int i, portLen;

	// trim leading whitespace (but keep the rest of the line)
	while (*in && isspace((unsigned char)*in)){
		in++;
	}

	// skip blank lines and comments
	if (Com_isStringComment(*in)){
		return qfalse;
	}

	// Skip non number //todo dns?
	/*if (*in < '0' || *in > '9'){
		return qfalse;
	}*/

	//dns valid
	if (!isalnum((unsigned char)*in)) {
		return qfalse;
	}

	portLen = 0;
	outIP[0] = '\0';
	outPort[0] = '\0';

	//port = qfalse;
	for (i = 0; i < (ADDRESS_LENGTHMAX -1); i++)
	{
		if (Com_isStringEOL(*in))
			break;

		//port
		if (*in == ':')
		{
			in++;
			for (; portLen < (PORT_LENGTH-1); portLen++)
			{
				if (Com_isStringEOL(*in))
					break;
				outPort[portLen] = *in;
				in++;
			}
			break;
		}
		outIP[i] = *in;
		in++;
	}
	//null terminate
	outIP[i] = '\0';
	outPort[portLen] = '\0';

	return qtrue;
}


