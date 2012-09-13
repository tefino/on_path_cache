#include <stdlib.h>
#include <stdio.h>

int main(int argc, char* arg[])
{
	char cmd[100] ;

	for(int i = 71 ; i <= 75 ; i++)
	{
		sprintf(cmd, "ssh root@172.16.20.%d \"/home/subscriber_opc 1000 20 10 100 1 120 > /tmp/client_output_opc.debug 2>&1 &\"", i) ;
		system(cmd) ;
	}
}