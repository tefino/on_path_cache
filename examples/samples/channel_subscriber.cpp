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

#include <signal.h>
#include <sys/time.h>

#include <blackadder.hpp>

Blackadder *ba;

int counter = 0;
struct timezone tz;
struct timeval start_tv;
struct timeval end_tv;
struct timeval duration;
bool experiment_started = false;
int payload_size = 1400;


using namespace std;

void *event_listener_loop(void *arg) {
    Blackadder *ba = (Blackadder *) arg;
    bool flag = true;
    cout << "event_listener_loop started " << endl;
    while (true) {
        Event ev;
        ba->getEvent(ev);
        if (ev.type == PUBLISHED_DATA) {
            char *p_data = (char *) ev.data;
            //cout<<"received data of size: "<< ev.data_len << endl;
            if (p_data[0] == 'A') {
                if (experiment_started == false) {
                    experiment_started = true;
                    gettimeofday(&start_tv, &tz);
                    printf("START TIME: %ld,%ld \n", start_tv.tv_sec, start_tv.tv_usec);
                }
                counter++;
            }
            if (p_data[0] == 'B') {
                //printf("Received %d packets\n", counter);
                gettimeofday(&end_tv, &tz);
                //printf("END TIME: %ld,%ld \n", end_tv.tv_sec, end_tv.tv_usec);
                duration.tv_sec = end_tv.tv_sec - start_tv.tv_sec;
                if (end_tv.tv_usec - start_tv.tv_usec > 0) {
                    duration.tv_usec = end_tv.tv_usec - start_tv.tv_usec;
                } else {
                    duration.tv_usec = end_tv.tv_usec + 1000000 - start_tv.tv_usec;
                    duration.tv_sec--;
                }
                printf("duration: %ld seconds and %d microseconds\n\n", duration.tv_sec, duration.tv_usec);
                float left = counter * ((float) payload_size / (float) (1024 * 1024));
                float right = ((float) ((duration.tv_sec * 1000000) + duration.tv_usec)) / 1000000;
                cout << "counter: " << counter << endl;
                cout << "payload_size: " << payload_size << endl;
                float throughput = (left / right);
                printf("Throughput: %f MB/sec \n\n", throughput);
                break;
            }
        } else {
            cout << "weird" << endl;
        }
    }
}

void sigfun(int sig) {
    (void) signal(SIGINT, SIG_DFL);
    ba->disconnect();
    delete ba;
    exit(0);
}

int main(int argc, char* argv[]) {
    pthread_t event_listener;
    (void) signal(SIGINT, sigfun);
    if (argc > 1) {
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
    cout << "Process ID: " << getpid() << endl;
    string id = "1111111111111111";
    string prefix_id = string();
    string bin_id = hex_to_chararray(id);
    string bin_prefix_id = hex_to_chararray(prefix_id);

    pthread_create(&event_listener, NULL, event_listener_loop, (void *) ba);

    ba->subscribe_scope(bin_id, bin_prefix_id, DOMAIN_LOCAL, NULL, 0);

    pthread_join(event_listener, NULL);
    cout << "disconnecting" << endl;
    sleep(1);
    ba->disconnect();
    delete ba;
    return 0;
}
