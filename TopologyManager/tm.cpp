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
#include <arpa/inet.h>
#include <set>
#include <blackadder.hpp>

#include "tm_igraph.hpp"

using namespace std;

Blackadder *ba;
TMIgraph tm_igraph;
pthread_t event_listener;

string req_id = "FFFFFFFFFFFFFFFE";
string req_prefix_id = string();
string req_bin_id = hex_to_chararray(req_id);
string req_bin_prefix_id = hex_to_chararray(req_prefix_id);

string resp_id = string();
string resp_prefix_id = "FFFFFFFFFFFFFFFD";
string resp_bin_id = hex_to_chararray(resp_id);
string resp_bin_prefix_id = hex_to_chararray(resp_prefix_id);

void handleRequest(char *request, int request_len) {
    unsigned char request_type;
    unsigned char no_publishers;
    unsigned char no_subscribers;
    string nodeID;
    set<string> publishers;
    set<string> subscribers;
    map<string, map<string,Bitvector *> > opresult = map<string, map<string, Bitvector *> >();
    map<string, map<string, pair<Bitvector*, unsigned int> > > kanycast_result ;
    map<string, Bitvector *> result = map<string, Bitvector *>();
    unsigned char response_type;
    int idx = 0;
    unsigned char strategy;
    int noofpub ;
    memcpy(&request_type, request, sizeof (request_type));
    memcpy(&strategy , request+ sizeof (request_type), sizeof (strategy));
    if( request_type == SCOPE_MATCH_PUB_SUB )
    {
        map<string, map<string, pair<Bitvector*, unsigned int> > >::iterator map_map_iter;
        map<string, pair<Bitvector*, unsigned int> >::iterator map_iter ;
        memcpy(&no_publishers, request + sizeof (request_type) + sizeof (strategy), sizeof (no_publishers));
        cout << "Publishers: ";
        for (int i = 0; i < (int) no_publishers; i++) {
            nodeID = string(request + sizeof (request_type) + sizeof (strategy) + sizeof (no_publishers) + idx, PURSUIT_ID_LEN);
            cout << nodeID << " ";
            idx += PURSUIT_ID_LEN;
            publishers.insert(nodeID);
        }
        cout << endl;
        cout << "Subscribers: ";
        memcpy(&no_subscribers, request + sizeof (request_type) + sizeof (strategy) + sizeof (no_publishers) + idx, sizeof (no_subscribers));
        for (int i = 0; i < (int) no_subscribers; i++) {
            nodeID = string(request + sizeof (request_type) + sizeof (strategy) + sizeof (no_publishers) + sizeof (no_subscribers) + idx, PURSUIT_ID_LEN);
            cout << nodeID << " ";
            idx += PURSUIT_ID_LEN;
            subscribers.insert(nodeID);
        }
        cout << endl;
        tm_igraph.calculateFID(publishers, subscribers, kanycast_result) ;
        for (map_map_iter = kanycast_result.begin(); map_map_iter != kanycast_result.end(); map_map_iter++) {
            // cout << "Publisher " << (*map_map_iter).first << ", FID: " << (*map_map_iter).second->to_string() << endl;
            response_type = SCOPE_PROBING;
            /*note that request_len includes request_type_len*/
            int response_size = request_len - sizeof(strategy) - sizeof (no_publishers) -\
            no_publishers * PURSUIT_ID_LEN - sizeof (no_subscribers) - no_subscribers * PURSUIT_ID_LEN +\
            sizeof(no_subscribers) + no_subscribers*FID_LEN + no_subscribers*PURSUIT_ID_LEN+no_subscribers*sizeof(int);
            char *response = (char *) malloc(response_size);
            memcpy(response, &response_type, sizeof (response_type));//add response_type
            int ids_index = sizeof (request_type) + sizeof (strategy) + sizeof (no_publishers) +\
            no_publishers * PURSUIT_ID_LEN + sizeof (no_subscribers) + no_subscribers * PURSUIT_ID_LEN;
            memcpy(response + sizeof (response_type), request + ids_index, request_len - ids_index);//add ids

            memcpy(response + sizeof (response_type) + request_len - ids_index ,\
                   &no_subscribers, sizeof(no_subscribers)) ;//add # of sub
            int i = 0 ;
            //add each subID and the corresponding FID and hop count
            for(map_iter = map_map_iter->second.begin() ; map_iter != map_map_iter->second.end() ; map_iter++)
            {
                memcpy(response + sizeof (response_type) + request_len - ids_index  +\
                       sizeof(no_subscribers)+i*PURSUIT_ID_LEN + i*FID_LEN+i*sizeof(int),\
                       (*map_iter).first.c_str(), PURSUIT_ID_LEN) ;
                memcpy(response + sizeof (response_type) + request_len - ids_index +\
                       sizeof(no_subscribers)+i*PURSUIT_ID_LEN + i*FID_LEN +i*sizeof(int)+ PURSUIT_ID_LEN,\
                       (*map_iter).second.first->_data, FID_LEN);
                memcpy(response + sizeof (response_type) + request_len - ids_index +\
                       sizeof(no_subscribers)+i*PURSUIT_ID_LEN + i*FID_LEN + i*sizeof(int)+PURSUIT_ID_LEN+FID_LEN,\
                       &(*map_iter).second.second, sizeof(unsigned int)) ;
                i++ ;
            }
            for(map_iter = map_map_iter->second.begin() ; map_iter != map_map_iter->second.end() ; map_iter++)
            {
                delete map_iter->second.first ;
            }
            /*find the FID to the publisher*/
            string destination = (*map_map_iter).first;
            Bitvector *FID_to_publisher = tm_igraph.calculateFID(tm_igraph.nodeID, destination);
            string response_id = resp_bin_prefix_id + (*map_map_iter).first;
            ba->publish_data(response_id, IMPLICIT_RENDEZVOUS, (char *) FID_to_publisher->_data, FID_LEN, response, response_size);
            delete FID_to_publisher;
            free(response);
        }

    }else if (request_type == MATCH_PUB_SUBS) {
        /*this a request for topology formation*/
        map<string, map<string, Bitvector* > >::iterator map_map_iter;
        map<string, Bitvector* >::iterator map_iter ;
        memcpy(&no_publishers, request + sizeof (request_type) + sizeof (strategy), sizeof (no_publishers));
        cout << "Publishers: ";
        for (int i = 0; i < (int) no_publishers; i++) {
            nodeID = string(request + sizeof (request_type) + sizeof (strategy) + sizeof (no_publishers) + idx, PURSUIT_ID_LEN);
            cout << nodeID << " ";
            idx += PURSUIT_ID_LEN;
            publishers.insert(nodeID);
        }
        cout << endl;
        cout << "Subscribers: ";
        memcpy(&no_subscribers, request + sizeof (request_type) + sizeof (strategy) + sizeof (no_publishers) + idx, sizeof (no_subscribers));
        for (int i = 0; i < (int) no_subscribers; i++) {
            nodeID = string(request + sizeof (request_type) + sizeof (strategy) + sizeof (no_publishers) + sizeof (no_subscribers) + idx, PURSUIT_ID_LEN);
            cout << nodeID << " ";
            idx += PURSUIT_ID_LEN;
            subscribers.insert(nodeID);
        }
        cout << endl;
        noofpub = publishers.size() ;
        tm_igraph.calculateFID(publishers, subscribers, result, opresult);/*opresult is pub sub FID*/
        /*notify publishers*/
        for (map_map_iter = opresult.begin(); map_map_iter != opresult.end(); map_map_iter++) {
             if (result[map_map_iter->first] == NULL) {
                cout << "Publisher " << (*map_map_iter).first << ", FID: NULL" << endl;
                response_type = STOP_PUBLISH;
                int response_size = request_len - sizeof(strategy) - sizeof (no_publishers) -\
                no_publishers * PURSUIT_ID_LEN - sizeof (no_subscribers) - no_subscribers * PURSUIT_ID_LEN;
                char *response = (char *) malloc(response_size);
                memcpy(response, &response_type, sizeof (response_type));
                int ids_index = sizeof (request_type) + sizeof (strategy) + sizeof (no_publishers) + no_publishers * PURSUIT_ID_LEN + sizeof (no_subscribers) + no_subscribers * PURSUIT_ID_LEN;
                memcpy(response + sizeof (response_type), request + ids_index, request_len - ids_index);
                /*find the FID to the publisher*/
                string destination = (*map_map_iter).first;
                Bitvector *FID_to_publisher = tm_igraph.calculateFID(tm_igraph.nodeID, destination);
                string response_id = resp_bin_prefix_id + (*map_map_iter).first;
                ba->publish_data(response_id, IMPLICIT_RENDEZVOUS, (char *) FID_to_publisher->_data, FID_LEN, response, response_size);
                delete FID_to_publisher;
                free(response);
            } else {
               // cout << "Publisher " << (*map_map_iter).first << ", FID: " << (*map_map_iter).second->to_string() << endl;
                response_type = START_PUBLISH;
                /*note that request_len includes request_type_len*/
                int response_size = request_len - sizeof(strategy) - sizeof (no_publishers) -\
                no_publishers * PURSUIT_ID_LEN - sizeof (no_subscribers) - no_subscribers * PURSUIT_ID_LEN + FID_LEN+\
                sizeof(no_subscribers) + no_subscribers*FID_LEN + no_subscribers*PURSUIT_ID_LEN;
                char *response = (char *) malloc(response_size);
                memcpy(response, &response_type, sizeof (response_type));//add response_type
                int ids_index = sizeof (request_type) + sizeof (strategy) + sizeof (no_publishers) +\
                no_publishers * PURSUIT_ID_LEN + sizeof (no_subscribers) + no_subscribers * PURSUIT_ID_LEN;
                memcpy(response + sizeof (response_type), request + ids_index, request_len - ids_index);//add ids
                memcpy(response + sizeof (response_type) + request_len - ids_index,\
                       result[(*map_map_iter).first]->_data, FID_LEN);//add compound id

                memcpy(response + sizeof (response_type) + request_len - ids_index + FID_LEN,\
                       &no_subscribers, sizeof(no_subscribers)) ;//add # of sub
                int i = 0 ;
                //add each subID and the corresponding FID
                for(map_iter = map_map_iter->second.begin() ; map_iter != map_map_iter->second.end() ; map_iter++)
                {
                    memcpy(response + sizeof (response_type) + request_len - ids_index + FID_LEN + sizeof(no_subscribers)+\
                           i*PURSUIT_ID_LEN + i*FID_LEN, (*map_iter).first.c_str(), PURSUIT_ID_LEN) ;
                    memcpy(response + sizeof (response_type) + request_len - ids_index + FID_LEN + sizeof(no_subscribers)+\
                           i*PURSUIT_ID_LEN + i*FID_LEN + PURSUIT_ID_LEN, (*map_iter).second->_data, FID_LEN);

                    i++ ;
                }
                for(map_iter = map_map_iter->second.begin() ; map_iter != map_map_iter->second.end() ; map_iter++)
                {
                    delete map_iter->second ;
                }
                memcpy(response + sizeof (response_type) + request_len - ids_index + FID_LEN + sizeof(no_subscribers)+\
                           i*PURSUIT_ID_LEN + i*FID_LEN +FID_LEN, &noofpub, sizeof(noofpub)) ;
                /*find the FID to the publisher*/
                string destination = (*map_map_iter).first;
                Bitvector *FID_to_publisher = tm_igraph.calculateFID(tm_igraph.nodeID, destination);
                string response_id = resp_bin_prefix_id + (*map_map_iter).first;
                ba->publish_data(response_id, IMPLICIT_RENDEZVOUS, (char *) FID_to_publisher->_data, FID_LEN, response, response_size);
                delete FID_to_publisher;
                delete result[(*map_map_iter).first];
                free(response);
            }
        }
    }else if ((request_type == SCOPE_PUBLISHED) || (request_type == SCOPE_UNPUBLISHED)) {
        /*this a request to notify subscribers about a new scope*/
        memcpy(&no_subscribers, request + sizeof (request_type) + sizeof (strategy), sizeof (no_subscribers));
        for (int i = 0; i < (int) no_subscribers; i++) {
            nodeID = string(request + sizeof (request_type) + sizeof (strategy) + sizeof (no_subscribers) + idx,\
                            PURSUIT_ID_LEN);
            Bitvector *FID_to_subscriber = tm_igraph.calculateFID(tm_igraph.nodeID, nodeID);
            int response_size = request_len - sizeof(strategy) - sizeof (no_subscribers) - no_subscribers * PURSUIT_ID_LEN + FID_LEN;
            int ids_index = sizeof (request_type) + sizeof (strategy) + sizeof (no_subscribers) + no_subscribers * PURSUIT_ID_LEN;
            char *response = (char *) malloc(response_size);
            string response_id = resp_bin_prefix_id + nodeID;
            memcpy(response, &request_type, sizeof (request_type));
            memcpy(response + sizeof (request_type), request + ids_index, request_len - ids_index);
            //cout << "PUBLISHING NOTIFICATION ABOUT NEW OR DELETED SCOPE to node " << nodeID << " using FID " << FID_to_subscriber->to_string() << endl;
            ba->publish_data(response_id, IMPLICIT_RENDEZVOUS, FID_to_subscriber->_data, FID_LEN, response, response_size);
            idx += PURSUIT_ID_LEN;
            delete FID_to_subscriber;
            free(response);
        }
    }else if((request_type == INFO_PUBLISHED))
    {
        memcpy(&no_publishers, request + sizeof (request_type) + sizeof (strategy), sizeof (no_publishers));
        for (int i = 0; i < (int) no_publishers; i++) {
            nodeID = string(request + sizeof (request_type) + sizeof (strategy) + sizeof (no_publishers) + idx,\
                            PURSUIT_ID_LEN);
            cout << nodeID << " ";
            idx += PURSUIT_ID_LEN;
            publishers.insert(nodeID);
        }
        memcpy(&no_subscribers, request + sizeof (request_type) + sizeof (strategy) + sizeof (no_publishers) + idx, sizeof (no_subscribers));
        for (int i = 0; i < (int) no_subscribers; i++) {
            nodeID = string(request + sizeof (request_type) + sizeof (strategy) + sizeof (no_publishers) +\
                            sizeof (no_subscribers) + idx, PURSUIT_ID_LEN);
            cout << nodeID << " ";
            idx += PURSUIT_ID_LEN;
            subscribers.insert(nodeID);
        }
        for (set<string>::iterator iter = subscribers.begin() ; iter != subscribers.end() ; iter++)
        {
            string subnodeid = *iter ;
            string bestnode ;
            Bitvector *FID_to_subscriber = tm_igraph.calculateFID(tm_igraph.nodeID, subnodeid);
            Bitvector to_pub_fid(FID_LEN*8) ;
            tm_igraph.calculateFID(subnodeid, publishers, to_pub_fid, bestnode);
            Bitvector *to_sub_fid =  tm_igraph.calculateFID(bestnode,subnodeid);
            int response_size = request_len-sizeof(strategy)-sizeof(no_publishers)-no_publishers*PURSUIT_ID_LEN-\
            sizeof(no_subscribers)-no_subscribers * PURSUIT_ID_LEN+ FID_LEN+FID_LEN+FID_LEN;
            int ids_index = sizeof (request_type) + sizeof (strategy) +sizeof (no_publishers) + no_publishers * PURSUIT_ID_LEN+\
            sizeof (no_subscribers) + no_subscribers * PURSUIT_ID_LEN;
            char *response = (char *) malloc(response_size);
            string response_id = resp_bin_prefix_id + subnodeid;
            memcpy(response, &request_type, sizeof (request_type));
            memcpy(response + sizeof (request_type), request + ids_index, request_len - ids_index);
            memcpy(response + sizeof (request_type)+request_len - ids_index, tm_igraph.nodeID_iLID[bestnode]->_data, FID_LEN) ;//internal LID
            memcpy(response + sizeof (request_type)+request_len - ids_index+FID_LEN, to_pub_fid._data, FID_LEN) ;
            memcpy(response + sizeof (request_type)+request_len - ids_index+FID_LEN+FID_LEN, to_sub_fid->_data, FID_LEN) ;
            //cout << "PUBLISHING NOTIFICATION ABOUT NEW OR DELETED SCOPE to node " << nodeID << " using FID " << FID_to_subscriber->to_string() << endl;
            ba->publish_data(response_id, IMPLICIT_RENDEZVOUS, FID_to_subscriber->_data, FID_LEN, response, response_size);
            idx += PURSUIT_ID_LEN;
            delete FID_to_subscriber;
            delete to_sub_fid ;
            free(response);
        }
    }
}

void *event_listener_loop(void *arg) {
    Blackadder *ba = (Blackadder *) arg;
    while (true) {
        Event ev;
        ba->getEvent(ev);
        if (ev.type == PUBLISHED_DATA) {
            //cout << "TM: received a request...processing now" << endl;
            handleRequest((char *) ev.data, ev.data_len);
        } else {
            cout << "TM: I am not expecting any other notification...FATAL" << endl;
        }
    }
}

void sigfun(int sig) {
    (void) signal(SIGINT, SIG_DFL);
    cout << "TM: disconnecting" << endl;
    ba->disconnect();
    delete ba;
    cout << "TM: exiting" << endl;
    exit(0);
}

int main(int argc, char* argv[]) {
    (void) signal(SIGINT, sigfun);
    cout << "TM: starting - process ID: " << getpid() << endl;
    if (argc != 2) {
        cout << "TM: the topology file is missing" << endl;
        exit(0);
    }
    /*read the graphML file that describes the topology*/
    if (tm_igraph.readTopology(argv[1]) < 0) {
        cout << "TM: couldn't read topology file...aborting" << endl;
        exit(0);
    }
    cout << "Blackadder Node: " << tm_igraph.nodeID << endl;
    /***************************************************/
    if (tm_igraph.mode.compare("kernel") == 0) {
        ba = Blackadder::Instance(false);
    } else {
        ba = Blackadder::Instance(true);
    }
    pthread_create(&event_listener, NULL, event_listener_loop, (void *) ba);
    ba->subscribe_scope(req_bin_id, req_bin_prefix_id, IMPLICIT_RENDEZVOUS, NULL, 0);

    pthread_join(event_listener, NULL);
    cout << "TM: disconnecting" << endl;
    ba->disconnect();
    delete ba;
    cout << "TM: exiting" << endl;
    return 0;
}
