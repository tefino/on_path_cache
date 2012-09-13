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

#include <assert.h>             // Needed for assert() macro
#include <stdio.h>              // Needed for printf()
#include <stdlib.h>             // Needed for exit() and ato*()
#include <math.h>               // Needed for pow()
#include <time.h>
#include <sys/time.h>

#include "blackadder.hpp"
#include <signal.h>
#include <setjmp.h>
#include <stdlib.h>

#include <iostream>
#include <vector>
#include <algorithm>
using namespace std ;


//----- Constants -----------------------------------------------------------
#define  FALSE          0       // Boolean false
#define  TRUE           1       // Boolean true

static unsigned int FILESIZE = 0 ;
static unsigned int CHUNKSIZE = 0 ;
static unsigned int SEGSIZE = 0 ;
static unsigned int NUMFILE = 0 ;
static unsigned int CLIENT_SIZE = 0;
static unsigned int RUNTIME = 0; //running time in sec
struct timespec time_to_wait1 ;
struct timespec time_to_wait2 ;
struct timespec time_left ;

int zipf(double alpha, int n);  // Returns a Zipf random variable
double   rand_val(int seed);         // Jain's RNG
static void       sig_alrm(int);
static jmp_buf    env_alrm;
static void
sig_alrm(int signo)
{
	siglongjmp(env_alrm, 1);
}


void client_process(int) ;

Blackadder *ba;

void sigfun(int sig) {
	(void) signal(SIGINT, SIG_DFL);
	ba->disconnect();
	delete ba;
	exit(0);
}

int main(int argc, char* argv[]) {
	(void) signal(SIGINT, sigfun);
	signal(SIGALRM, sig_alrm) ;
	time_to_wait1.tv_sec = 0 ;
	time_to_wait1.tv_nsec = 1000000 ;
	time_to_wait2.tv_nsec = 0 ;
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
	if(argc != 7){
		cout<<"parameter error"<<endl ;
		return 0 ;
	}

	FILESIZE = atoi(argv[1]) ;
	CHUNKSIZE = atoi(argv[2]) ;
	SEGSIZE = atoi(argv[3]) ;
	NUMFILE = atoi(argv[4]) ;
	CLIENT_SIZE = atoi(argv[5]);
	RUNTIME = atoi(argv[6]) ; //running time in sec
	cout<<"FILESIZE:"<<FILESIZE<<" CHUNKSIZE:"<<CHUNKSIZE<<" SEGSIZE:"<<SEGSIZE<<" NUMFILE:"<<" CLIENT_SIZE:"<<" RUNTIME:"<<RUNTIME<<endl ;

	int i = 0 ;
	for( i = 1 ; i < CLIENT_SIZE ; i++ )
	{
		pid_t pid ;
		if( (pid = fork()) < 0 )
		{
			cout<<"fork error"<<endl ;
		}
		if( pid == 0 )
		{
			(void) signal(SIGINT, sigfun) ;
			signal(SIGALRM, sig_alrm) ;
			client_process(i) ;
			return 0 ;
		}
	}
	i = CLIENT_SIZE ;
	client_process(i) ;
}
void client_process(int i)
{
	FILE *f ;
	char docname[255] ;
	srand((unsigned int)(time(NULL)+getpid())) ;
	sprintf(docname, "/home/client_process_opc%d.dat", i) ;
	if( (f = fopen(docname, "w+")) == NULL)
	{
		cout<<"process"<<i<<" fopen error"<<endl ;
	}
	unsigned int file_num = 0 ;
	unsigned int nooffile = 0 ;
	rand_val(time(NULL)+getpid()) ;
	vector<unsigned int> vec_file ;

	time_t begintime = time(NULL) ;
	time_t endtime = time(NULL) ;
	while(difftime(endtime, begintime) < RUNTIME)
	{
		if(nooffile >= NUMFILE && NUMFILE != 0)
		{
			break ;
		}
		nooffile++ ;
		string bin_prefix_id ;
		string bin_id ;
		file_num = zipf(1.0, FILESIZE) ;
		vec_file.push_back(file_num) ;
		string fileid ;
		char filename[10] ;
		sprintf(filename, "%X", file_num) ;
		fileid.insert(0, 2*PURSUIT_ID_LEN-strlen(filename), '0') ;
		fileid += filename ;
		fprintf(f, "%d  ", file_num) ;
		fflush(f) ;

		unsigned int chunk_num = 1 ;
		struct timeval tv1, tv2 ;
		gettimeofday(&tv1, NULL) ;
		while(chunk_num <= CHUNKSIZE)
		{
			if (sigsetjmp(env_alrm,1) != 0){
				cout<<"timeout"<<endl;
			}
			string chunkid ;
			char chunkname[10] ;
			sprintf(chunkname, "%X", chunk_num) ;
			chunkid.insert(0, 2*PURSUIT_ID_LEN - strlen(chunkname), '0') ;
			chunkid += chunkname ;

			bin_id = hex_to_chararray(chunkid) ;
			bin_prefix_id = hex_to_chararray(fileid) ;
			ba->subscribe_scope(bin_id, bin_prefix_id, DOMAIN_LOCAL, NULL, 0);
			unsigned int item_num = 0 ;
			while (item_num < SEGSIZE) {
				alarm(10);
				Event ev;
				ba->getEvent(ev);
				switch (ev.type) {
		case SCOPE_PUBLISHED:
			cout << "SCOPE_PUBLISHED: " << chararray_to_hex(ev.id) << endl;
			bin_id = ev.id.substr(ev.id.length() - PURSUIT_ID_LEN, PURSUIT_ID_LEN);
			bin_prefix_id = ev.id.substr(0, ev.id.length() - PURSUIT_ID_LEN);
			ba->subscribe_scope(bin_id, bin_prefix_id, DOMAIN_LOCAL, NULL, 0);
			break;
		case SCOPE_UNPUBLISHED:
			cout << "SCOPE_UNPUBLISHED: " << chararray_to_hex(ev.id) << endl;
			break;
		case START_PUBLISH:
			cout << "START_PUBLISH: " << chararray_to_hex(ev.id) << endl;
			break;
		case STOP_PUBLISH:
			cout << "STOP_PUBLISH: " << chararray_to_hex(ev.id) << endl;
			break;
		case PUBLISHED_DATA:
			item_num++ ;
			cout << "PUBLISHED_DATA: " << chararray_to_hex(ev.id) << endl;
			cout << "data size: " << ev.data_len << endl;
			break;
				}
			}
			alarm(0);
			chunk_num++ ;
		}
		gettimeofday(&tv2, NULL) ;
		float td = 1000000*(tv2.tv_sec - tv1.tv_sec)+tv2.tv_usec - tv1.tv_usec ;
		fprintf(f, "%f\n", td) ;
		time_to_wait2.tv_sec = (unsigned int) random()%3 ;
		nanosleep(&time_to_wait2, NULL) ;
	}
	fclose(f) ;
	ba->disconnect();
	delete ba;
	return ;
}




int zipf(double alpha, int n)
{
	static int first = TRUE;      // Static first time flag
	static double c = 0;          // Normalization constant
	double z;                     // Uniform random number (0 < z < 1)
	double sum_prob;              // Sum of probabilities
	double zipf_value;            // Computed exponential value to be returned
	int    i;                     // Loop counter

	// Compute normalization constant on first call only
	if (first == TRUE)
	{
		for (i=1; i<=n; i++)
			c = c + (1.0 / pow((double) i, alpha));
		c = 1.0 / c;
		first = FALSE;
	}

	// Pull a uniform random number (0 < z < 1)
	do
	{
		z = rand_val(0.0);
	}
	while ((z == 0) || (z == 1));

	// Map z to the value
	sum_prob = 0;
	for (i=1; i<=n; i++)
	{
		sum_prob = sum_prob + c / pow((double) i, alpha);
		if (sum_prob >= z)
		{
			zipf_value = i;
			break;
		}
	}

	// Assert that zipf_value is between 1 and N
	assert((zipf_value >=1) && (zipf_value <= n));

	return(zipf_value);
}

double rand_val(int seed)
{
	const long  a =      16807;  // Multiplier
	const long  m = 2147483647;  // Modulus
	const long  q =     127773;  // m div a
	const long  r =       2836;  // m mod a
	static long x;               // Random int value
	long        x_div_q;         // x divided by q
	long        x_mod_q;         // x modulo q
	long        x_new;           // New x value

	// Set the seed if argument is non-zero and then return zero
	if (seed > 0)
	{
		x = seed;
		return(0.0);
	}

	// RNG using integer arithmetic
	x_div_q = x / q;
	x_mod_q = x % q;
	x_new = (a * x_mod_q) - (r * x_div_q);
	if (x_new > 0)
		x = x_new;
	else
		x = x_new + m;

	// Return a random value between 0.0 and 1.0
	return((double) x / m);
}




