/*
* Copyright (C) 2010-2011  George Parisis and Dirk Trossen
* All rights reserved.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License version
* 2 as published by the Free Software Foundation.
*
* Alternatively, this software may be distributed under the terms of
* the BSD license.
*
* See LICENSE and COPYING for more details.
*/

#include <blackadder.hpp>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

static unsigned int FILESIZE = 0 ;
static unsigned int CHUNKSIZE = 0 ;
static unsigned int SEGSIZE = 0 ;

Blackadder *ba;
int payload_size = 1300 ;
char *payload = (char *) malloc(payload_size);
static unsigned int data_sent_num = 0 ;

void sigfun(int sig) {
	(void) signal(SIGINT, SIG_DFL) ;
	FILE *fp ;
	if ( (fp = fopen("/home/server_opc.dat", "w+")) == NULL )
	{
		cout<<"server.dat open fail"<<endl ;
		ba->disconnect();
		free(payload);
		delete ba;
		exit(0);
	}
	fprintf(fp, "total data sent in byte: %d", data_sent_num*payload_size) ;
	fclose(fp) ;
	ba->disconnect();
	free(payload);
	delete ba;
	exit(0);
}

void termfun(int sig){
	(void) signal(SIGTERM, SIG_DFL) ;
	FILE *fp ;
	if ( (fp = fopen("/home/server_opc.dat", "w+")) == NULL )
	{
		cout<<"server.dat open fail"<<endl ;
		ba->disconnect();
		free(payload);
		delete ba;
		exit(0);
	}
	fprintf(fp, "total data sent in byte: %d", data_sent_num*payload_size) ;
	fclose(fp) ;
	ba->disconnect();
	free(payload);
	delete ba;
	exit(0);
}

int main(int argc, char* argv[]) {
	(void) signal(SIGINT, sigfun);
	(void) signal(SIGTERM, termfun) ;
	if (argc == 1) {
		int user_or_kernel = atoi(argv[1]);
		if (user_or_kernel == 0) {
			ba = Blackadder::Instance(true);
		} else {
			ba = Blackadder::Instance(false);
		}
	} else {
		/*By Default I assume blackadder is running in user space*/
		ba = Blackadder::Instance(true);
	}
	//cout << "Process ID: " << getpid() << endl;

	if(argc != 4) {
		cout<<"parameter error"<<endl ;
		return 0 ;
	}
	FILESIZE = atoi(argv[1]) ;
	CHUNKSIZE = atoi(argv[2]) ;
	SEGSIZE = atoi(argv[3]) ;
	cout<<"FILESIZE:"<<FILESIZE<<" CHUNKSIZE:"<<CHUNKSIZE<<" SEGSIZE:"<<SEGSIZE<<endl ;

	unsigned int file_num = 1 ;
	string bin_prefix_id ;
	string bin_id ;
	while(file_num <= FILESIZE)
	{
		string fileid ;
		char filename[10] ;
		sprintf(filename, "%X", file_num) ;
		fileid.insert(0, 2*PURSUIT_ID_LEN-strlen(filename), '0') ;
		fileid += filename ;

		string prefix_id ;
		bin_id = hex_to_chararray(fileid);
		bin_prefix_id = hex_to_chararray(prefix_id);
		ba->publish_scope(bin_id, bin_prefix_id, DOMAIN_LOCAL, NULL, 0);
		usleep(10) ;
		file_num++ ;
	}
	file_num = 1 ;
	while(file_num <= FILESIZE)
	{
		string fileid ;
		char filename[10] ;
		sprintf(filename, "%X", file_num) ;
		fileid.insert(0, 2*PURSUIT_ID_LEN-strlen(filename), '0') ;
		fileid += filename ;

		unsigned int chunk_num = 1 ;
		while(chunk_num <= CHUNKSIZE)
		{
			string chunkid ;
			char chunkname[10] ;
			sprintf(chunkname, "%X", chunk_num) ;
			chunkid.insert(0, 2*PURSUIT_ID_LEN - strlen(chunkname), '0') ;
			chunkid += chunkname ;

			bin_id = hex_to_chararray(chunkid) ;
			bin_prefix_id = hex_to_chararray(fileid) ;
			ba->publish_scope(bin_id, bin_prefix_id, DOMAIN_LOCAL, NULL, 0);
			usleep(1000) ;
			chunk_num++ ;
		}
		file_num++ ;
	}

	file_num = 1 ;
	while(file_num <= FILESIZE)
	{
		string fileid ;
		char filename[10] ;
		sprintf(filename, "%X", file_num) ;
		fileid.insert(0, 2*PURSUIT_ID_LEN-strlen(filename), '0') ;
		fileid += filename ;

		unsigned int chunk_num = 1 ;
		while(chunk_num <= CHUNKSIZE)
		{
			string chunkid ;
			char chunkname[10] ;
			sprintf(chunkname, "%X", chunk_num) ;
			chunkid.insert(0, 2*PURSUIT_ID_LEN - strlen(chunkname), '0') ;
			chunkid += chunkname ;

			unsigned int seg_num = 1 ;
			string file_chunk_id = fileid + chunkid ;
			while(seg_num <= SEGSIZE)
			{
				string segid ;
				char segname[10] ;
				sprintf(segname, "%X", seg_num) ;
				segid.insert(0, 2*PURSUIT_ID_LEN - strlen(segname), '0') ;
				segid += segname ;

				bin_id = hex_to_chararray(segid) ;
				bin_prefix_id = hex_to_chararray(file_chunk_id) ;
				ba->publish_info(bin_id, bin_prefix_id, DOMAIN_LOCAL, NULL, 0) ;
				usleep(1000) ;
				seg_num++ ;
			}
			chunk_num++ ;
		}
		file_num++ ;
	}
	cout<<"ready to sent"<<endl ;
	while (true) {
		Event ev;
		ba->getEvent(ev);
		switch (ev.type) {
			case SCOPE_PUBLISHED:
				cout << "SCOPE_PUBLISHED: " << chararray_to_hex(ev.id) << endl;
				break;
			case SCOPE_UNPUBLISHED:
				cout << "SCOPE_UNPUBLISHED: " << chararray_to_hex(ev.id) << endl;
				break;
			case PLEASE_PUSH_DATA:
				data_sent_num++ ;
				cout << "PLEASE_PUSH_DATA: " << chararray_to_hex(ev.id) << endl;
				ba->publish_data(ev.id, IMPLICIT_RENDEZVOUS, ev.to_sub_FID._data, FID_LEN, payload, payload_size);
				break;
			case STOP_PUBLISH:
				cout << "STOP_PUBLISH: " << chararray_to_hex(ev.id) << endl;
				break ;
			case PUBLISHED_DATA:
				cout << "PUBLISHED_DATA: " << chararray_to_hex(ev.id) << endl;
				break ;
		}
	}
	sleep(5);
	free(payload);
	ba->disconnect();
	delete ba;
	return 0;
}
