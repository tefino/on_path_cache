#include <stdlib.h>
#include <stdio.h>

int main(int argc, char* arg[])
{
	char cmd[100] ;

	for(int i = 68 ; i <= 70 ; i++)
	{
		sprintf(cmd, "ssh root@172.16.20.%d \"pkill publisher_opc\"", i) ;
		system(cmd) ;
	}
}