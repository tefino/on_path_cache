#include <stdlib.h>
#include <stdio.h>

int main(int argc, char* arg[])
{
	char cmd[100] ;

	for(int i = 71 ; i <= 75 ; i++)
	{
		sprintf(cmd, "ssh root@172.16.20.%d \"pkill subscriber_opc\"", i) ;
		system(cmd) ;
	}
}