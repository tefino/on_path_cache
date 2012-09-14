#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
	char cmd[100] ;
	int i = atoi(argv[1]) ;
	sprintf(cmd, "ssh root@172.16.20.%d \"/home/publisher_opc 1000 20 1 > /tmp/publisher_output_opc.debug 2>&1 &\"", i) ;
	system(cmd) ;
}