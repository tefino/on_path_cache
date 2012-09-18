/*Our Proposal
 *This is the element that manipulate cache mechanism
*/
#include "cacheunit.hh"

CLICK_DECLS

bool CacheEntry::matchIID(Vector<String>& fullIDs)
{
    String IID ;
    IID = fullIDs[0].substring(fullIDs[0].length() - PURSUIT_ID_LEN, PURSUIT_ID_LEN) ;//get the information ID
    String tempSID ;
    Vector<String> forSIDupdate ;
    Vector<String>::iterator input_iter ;
    Vector<String>::iterator SIDs_iter ;
    Vector<String>::iterator IID_iter ;
    bool ret = false ;
    bool updateSID = false ;
    for( input_iter = fullIDs.begin() ; input_iter != fullIDs.end() ; input_iter++)//for each input ID
    {
        tempSID = input_iter->substring(0, input_iter->length()-PURSUIT_ID_LEN) ;//get the Scope ID
        forSIDupdate.push_back(tempSID) ;
        for(SIDs_iter = SIDs.begin() ; SIDs_iter != SIDs.end() ; SIDs_iter++)//for each local cache Scope ID
        {
            if(!(tempSID.compare(*SIDs_iter)))
            {
                updateSID = true ;
                for(IID_iter = IIDs.begin() ; IID_iter != IIDs.end() ; IID_iter++)
                {
                    if( !(IID.compare(*IID_iter)))
                        ret = true ;
                }
            }
        }
    }
    if(updateSID == true)
        SIDs = forSIDupdate ;
    return ret ;
}

bool CacheEntry::matchSID(String SID)
{
    Vector<String>::iterator sid_iter ;
    for(sid_iter = SIDs.begin() ; sid_iter != SIDs.end() ; sid_iter++)
    {
        if(!(SID.compare(*sid_iter)))
        {
            return true ;
        }
    }
    return false ;
}
bool CacheEntry::matchSID(Vector<String> _SIDs)
{
    Vector<String>::iterator sid_iter ;
    bool ret = false ;
    for(sid_iter = SIDs.begin() ; sid_iter != SIDs.end() ; sid_iter++)
    {
        for(Vector<String>::iterator _sid_iter = _SIDs.begin() ; _sid_iter != _SIDs.end() ; _sid_iter++)
        if(!(_sid_iter->compare(*sid_iter)))
        {
            ret = true ;
            break ;
        }
    }
    if(ret)
        SIDs = _SIDs ;
    return ret ;
}


CacheUnit::CacheUnit(){}
CacheUnit::~CacheUnit(){click_chatter("CacheUnit: destroyed!");}

int CacheUnit::configure(Vector<String> &conf, ErrorHandler *errh)
{
    gc = (GlobalConf*) cp_element(conf[0], this) ;
	cp_integer(conf[1], &cache_size);
	click_chatter("CU--cache_size: %d", cache_size) ;
    return 0 ;
}
int CacheUnit::initialize(ErrorHandler *errh)
{
    current_size = 0 ;
    cache.clear() ;

	Billion = 1000000000 ;
	cache_hit = 0 ;
	cache_hit_Bill = 0 ;
	cache_replace = 0 ;
	cache_replace_Bill = 0 ;
    return 0 ;
}
void CacheUnit::cleanup(CleanupStage stage)
{
	FILE *ft ;
	if( (ft = fopen("/home/cacheunit_opc.dat", "w+")) == NULL )
		click_chatter("cacheunit fopen error");
	fprintf(ft, "cache_hit: %d\ncache_hit_Bill: %d\ncache_replace: %d\ncache_replace_Bill: %d\n",
		cache_hit, cache_hit_Bill, cache_replace, cache_replace_Bill) ;
	fprintf(ft, "total_cache_number_chunk: %d\n", cache.size()) ;
	for( int i = 0 ; i < cache.size() ; i++)
	{
		fprintf(ft, "%s\n", cache[i]->SIDs[0].quoted_hex().c_str()) ;
	}
	fclose(ft) ;

    if(stage >= CLEANUP_CONFIGURED)
    {
        for(int i = 0 ; i < cache.size() ; i++)
        {
            CacheEntry* ce = cache.at(i) ;
            delete ce ;
        }
    }
}
void CacheUnit::push(int port, Packet *p)
{
    BABitvector FID(FID_LEN*8) ;
    unsigned char numberOfIDs ;
    unsigned char IDLength /*in fragments of PURSUIT_ID_LEN each*/;
    unsigned char prefixIDLength /*in fragments of PURSUIT_ID_LEN each*/ ;
    Vector<String> IDs;
    Vector<CacheEntry*>::iterator cache_iter ;
    int index = 0 ;
    if(port == 0)//this is a probing message
    {
        int numberOfInfoIDs ;
        Vector<String> IIDs ;
        Vector<String>::iterator iiditer ;
        BABitvector BFforIID(PURSUIT_ID_LEN*8) ;
        unsigned char hop_count ;
        unsigned char origin ;
        int i = 0 ;
        IIDs.clear() ;
        if (gc->use_mac) {
            memcpy(FID._data, p->data() + 14, FID_LEN);
        } else {
            return ;//right now only support ethernet level
        }
        memcpy(&numberOfIDs, p->data()+14+FID_LEN, sizeof(numberOfIDs)) ;//# of IDs
        for (int i = 0; i < (int) numberOfIDs; i++) {
            IDLength = *(p->data()+14+FID_LEN+sizeof(numberOfIDs)+index);
            IDs.push_back(String((const char *) (p->data()+14+FID_LEN+sizeof(numberOfIDs)+sizeof(IDLength)+index),\
                                IDLength * PURSUIT_ID_LEN));
            index = index + sizeof (IDLength) + IDLength * PURSUIT_ID_LEN;
        }
        memcpy(&hop_count, p->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN, sizeof(hop_count)) ;//assign hop_count
        memcpy(&origin, p->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN+sizeof(hop_count)+FID_LEN, sizeof(origin)) ;
        WritablePacket* packet = p->uniqueify() ;

        for(cache_iter = cache.begin() ; cache_iter != cache.end() ; cache_iter++)
        {
            if((*cache_iter)->matchIID(IDs))
            {
                hop_count = 0 ;//start from 0
                origin = 1 ;//origin is cache
                memcpy(packet->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN, &hop_count, sizeof(hop_count)) ;
                memcpy(packet->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN+sizeof(hop_count), gc->iLID._data, FID_LEN) ;
                memcpy(packet->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN+sizeof(hop_count)+FID_LEN, &origin, sizeof(origin)) ;
                packet->set_anno_u32(0, (uint32_t)(index+sizeof(numberOfIDs)+FID_LEN+14)) ;
                output(0).push(packet) ;
                return ;
            }
        }
        hop_count++ ;
        memcpy(packet->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN, &hop_count, sizeof(hop_count)) ;
        packet->set_anno_u32(0, (uint32_t)(index+sizeof(numberOfIDs)+FID_LEN+14)) ;
        output(0).push(packet) ;
    }
    else if(port == 1)
    {
        /*this is a subinfo packet*/
        memcpy(FID._data, p->data()+14, FID_LEN) ;
        BABitvector testFID(FID_LEN*8) ;
        testFID = FID & gc->iLID ;
        if(testFID == gc->iLID)
        {
            bool cachefound = false ;
            BABitvector backFID(FID_LEN*8) ;
            memcpy(&numberOfIDs, p->data()+14+FID_LEN, sizeof(numberOfIDs)) ;//# of IDs
            for (int i = 0; i < (int) numberOfIDs; i++) {
                IDLength = *(p->data()+14+FID_LEN+sizeof(numberOfIDs)+index);
                IDs.push_back(String((const char *) (p->data()+14+FID_LEN+sizeof(numberOfIDs)+sizeof(IDLength)+index),\
                                    IDLength * PURSUIT_ID_LEN));
                index = index + sizeof (IDLength) + IDLength * PURSUIT_ID_LEN;
            }
            memcpy(backFID._data, p->data()+14+FID_LEN+sizeof(numberOfIDs)+index, FID_LEN) ;

            for(cache_iter = cache.begin() ; cache_iter != cache.end() ; cache_iter++)
            {
                if((*cache_iter)->matchIID(IDs))
                {//local cache found
                    cachefound = true ;
                    int reverse_proto ;
                    int prototype ;
                    cp_integer(String("0x080d"), 16, &reverse_proto);
                    prototype = htons(reverse_proto);
                    WritablePacket* packet ;

                    String infoID = IDs[0].substring(IDs[0].length()-PURSUIT_ID_LEN, PURSUIT_ID_LEN) ;
                    if((*cache_iter)->_data_length[infoID] > FID_LEN+2*PURSUIT_ID_LEN)
                        packet = p->put((*cache_iter)->_data_length[infoID] - (FID_LEN+2*PURSUIT_ID_LEN)) ;
                    else
                    {
                        p->take((FID_LEN+2*PURSUIT_ID_LEN) - ((*cache_iter)->_data_length[infoID])) ;
                        packet = p->uniqueify() ;
                    }

                    memcpy(packet->data()+12, &prototype, 2) ;
                    memcpy(packet->data()+14, backFID._data, FID_LEN) ;
                    memcpy(packet->data()+14+FID_LEN+sizeof(numberOfIDs)+index, (*cache_iter)->_data[infoID],\
                           (*cache_iter)->_data_length[infoID]) ;
                    output(1).push(packet) ;
                    break ;
                }
            }
            if(!cachefound)
            {//if get here, it means that the local cache has been flushed, so the forwarder must redirect the xubinfo
            //request to the final publisher

                unsigned char type = PLEASE_PUSH_DATA ;
                unsigned char idno = 1 ;
                unsigned char iidlen = 2 ;
                String notificationIID ;
                Vector<String>::iterator vec_str_iter ;
                int total_ID_length = 0 ;
                int packet_len ;
                int IDindex = 0 ;
                WritablePacket* packet ;

                notificationIID = String((const char*)(p->data()+14+FID_LEN+sizeof(numberOfIDs)+index+FID_LEN),\
                                         iidlen*PURSUIT_ID_LEN) ;
                for( vec_str_iter = IDs.begin() ; vec_str_iter != IDs.end() ; vec_str_iter++)
                {
                    total_ID_length += vec_str_iter->length() ;
                }
                packet_len = FID_LEN/*FID to pub*/+sizeof(idno)+sizeof(iidlen)+iidlen*PURSUIT_ID_LEN/*the previous segments are RVnotification header*/+\
                sizeof(type)/*type*/+sizeof(numberOfIDs)/*numberofID*/+numberOfIDs*sizeof(IDLength)/*number of fragment*/+\
                total_ID_length/*IDs*/+FID_LEN/*for data push*/ ;
                packet = Packet::make(packet_len) ;
                memcpy(packet->data(), FID._data, FID_LEN) ;
                memcpy(packet->data()+FID_LEN, &idno, sizeof(idno)) ;
                memcpy(packet->data()+FID_LEN+sizeof(idno), &iidlen, sizeof(iidlen)) ;
                memcpy(packet->data()+FID_LEN+sizeof(idno)+sizeof(iidlen), notificationIID.c_str(), iidlen*PURSUIT_ID_LEN) ;
                memcpy(packet->data()+FID_LEN+sizeof(idno)+sizeof(iidlen)+iidlen*PURSUIT_ID_LEN, &type, sizeof(type)) ;
                memcpy(packet->data()+FID_LEN+sizeof(idno)+sizeof(iidlen)+iidlen*PURSUIT_ID_LEN+sizeof(type),\
                       &numberOfIDs, sizeof(numberOfIDs)) ;
                for( vec_str_iter = IDs.begin() ; vec_str_iter != IDs.end() ;vec_str_iter++)//ID length ID
                {
                    IDLength = vec_str_iter->length()/PURSUIT_ID_LEN ;
                    memcpy(packet->data()+FID_LEN+sizeof(idno)+sizeof(iidlen)+iidlen*PURSUIT_ID_LEN+\
                           sizeof(type)+sizeof(numberOfIDs)+IDindex, &IDLength, sizeof(IDLength)) ;
                    memcpy(packet->data()+FID_LEN+sizeof(idno)+sizeof(iidlen)+iidlen*PURSUIT_ID_LEN+\
                           sizeof(type)+sizeof(numberOfIDs)+IDindex+sizeof(IDLength), vec_str_iter->c_str(),\
                           vec_str_iter->length()) ;
                    IDindex += sizeof(IDLength)+vec_str_iter->length() ;
                }
                memcpy(packet->data()+FID_LEN+sizeof(idno)+sizeof(type)+sizeof(numberOfIDs)+IDindex,\
                       backFID._data, FID_LEN) ;
                output(2).push(packet) ;
            }
        }
        else
        {
            output(1).push(p) ;
        }
    }
    else if(port == 2)
    {
        Vector<String> IIDs ;
        int i = 0 ;
        bool cachefound = false ;
        char* data ;
        unsigned int datalen ;
        IIDs.clear() ;
        if (gc->use_mac) {
            memcpy(FID._data, p->data() + 14, FID_LEN);
        } else {
            return ;//right now only support ethernet level
        }
        memcpy(&numberOfIDs, p->data()+14+FID_LEN, sizeof(numberOfIDs)) ;//# of IDs
        for (int i = 0; i < (int) numberOfIDs; i++) {
            IDLength = *(p->data()+14+FID_LEN+sizeof(numberOfIDs)+index);
            IDs.push_back(String((const char *) (p->data()+14+FID_LEN+sizeof(numberOfIDs)+sizeof(IDLength)+index),\
                                IDLength * PURSUIT_ID_LEN));
            index = index + sizeof (IDLength) + IDLength * PURSUIT_ID_LEN;
        }
        datalen = p->length() - (14+FID_LEN+sizeof(numberOfIDs)+index) ;
        data = (char*)malloc(datalen) ;
        memcpy(data, p->data()+14+FID_LEN+sizeof(numberOfIDs)+index, datalen) ;
        if(IDs.size() == 1 && !(IDs[0].substring(0,PURSUIT_ID_LEN-1).compare((gc->RVScope).substring(0, PURSUIT_ID_LEN-1))))
        {
            output(3).push(p) ;
        }
        else
        {
            storecache(IDs, data, datalen) ;
            output(3).push(p) ;
        }
    }
    else if(port == 3)
    {
        unsigned char type ;
        if (gc->use_mac) {
            memcpy(FID._data, p->data() + 14, FID_LEN);
        } else {
            return ;//right now only support ethernet level
        }
        memcpy(&type, p->data()+14+FID_LEN, sizeof(type)) ;
        memcpy(&numberOfIDs, p->data()+14+FID_LEN+sizeof(type), sizeof(numberOfIDs)) ;//# of IDs
        for (int i = 0; i < (int) numberOfIDs; i++) {
            IDLength = *(p->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index);
            IDs.push_back(String((const char *) (p->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+sizeof(IDLength)+index),\
                                IDLength * PURSUIT_ID_LEN));
            index = index + sizeof (IDLength) + IDLength * PURSUIT_ID_LEN;
        }
        switch (type)
        {
            case SCOPE_PROBING_MESSAGE:
            {
                BloomFilter BFforIID(IBFSIZE*8) ;
                unsigned int hop_passed ;
                unsigned int total_distance ;
                unsigned int noofcache ;
                unsigned int hop_count ;

                memcpy(BFforIID.data._data, p->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index, IBFSIZE) ;
                memcpy(&hop_passed, p->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index+\
                       IBFSIZE+FID_LEN, sizeof(hop_passed)) ;
                memcpy(&total_distance, p->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index+\
                       IBFSIZE+FID_LEN+sizeof(hop_passed), sizeof(total_distance)) ;
                memcpy(&noofcache, p->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index+\
                       IBFSIZE+FID_LEN+sizeof(hop_passed)+sizeof(total_distance), sizeof(noofcache)) ;
                memcpy(&hop_count, p->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index+\
                       IBFSIZE+FID_LEN+sizeof(hop_passed)+sizeof(total_distance)+sizeof(noofcache),\
                       sizeof(hop_count)) ;
                hop_passed++ ;

                WritablePacket* packet = p->uniqueify() ;
                for(cache_iter = cache.begin() ; cache_iter != cache.end() ; cache_iter++)
                {
                    if((*cache_iter)->matchSID(IDs))
                    {
                        Vector<String>::iterator iter ;
                        for(iter = (*cache_iter)->IIDs.begin() ; iter != (*cache_iter)->IIDs.end() ; iter++)
                        {
                            BFforIID.add2bf(*iter) ;
                        }
                        total_distance += ((*cache_iter)->IIDs.size())*(hop_count-hop_passed) ;
                        noofcache += (*cache_iter)->IIDs.size() ;
                        memcpy(packet->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index,\
                               BFforIID.data._data, IBFSIZE) ;
                        memcpy(packet->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index+\
                                IBFSIZE+FID_LEN, &hop_passed,sizeof(hop_passed)) ;
                        memcpy(packet->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index+\
                                IBFSIZE+FID_LEN+sizeof(hop_passed), &total_distance,sizeof(total_distance)) ;
                        memcpy(packet->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index+\
                                IBFSIZE+FID_LEN+sizeof(hop_passed)+sizeof(total_distance),&noofcache,  sizeof(noofcache)) ;
                        packet->set_anno_u32(0, (uint32_t)(IBFSIZE+index+sizeof(numberOfIDs)+sizeof(type)+FID_LEN+14)) ;
                        output(4).push(packet) ;
                        return ;
                    }
                }
                packet->set_anno_u32(0, (uint32_t)(IBFSIZE+index+sizeof(numberOfIDs)+sizeof(type)+FID_LEN+14)) ;
                output(4).push(packet) ;
                break ;
            }
            case SUB_SCOPE_MESSAGE:
            {
                for(cache_iter = cache.begin() ; cache_iter != cache.end() ; cache_iter++)
                {
                    if((*cache_iter)->matchSID(IDs))
                    {
                        BloomFilter ebf(EBFSIZE*8) ;
                        BloomFilter ibf(IBFSIZE*8) ;
                        BABitvector to_sub_FID(FID_LEN*8) ;
                        memcpy(ebf.data._data, p->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index, EBFSIZE) ;
                        memcpy(ibf.data._data, p->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index+IBFSIZE, IBFSIZE) ;
                        memcpy(to_sub_FID._data, p->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index+IBFSIZE+EBFSIZE, FID_LEN) ;

                        Vector<String> infoIDs ;
                        for(Vector<String>::iterator iter = (*cache_iter)->IIDs.begin() ; iter != (*cache_iter)->IIDs.end() ; iter++)
                        {
                            if(!ebf.test(*iter) && ibf.test(*iter))
                            {
                                ebf.add2bf(*iter) ;
                                infoIDs.push_back(*iter) ;
                            }
                        }
                        if(infoIDs.empty())
                        {
                            output(5).push(p) ;
                            return ;
                        }

                        else
                        {
							cache_hit++ ;
							if(cache_hit == Billion)
							{
								cache_hit = 0 ;
								cache_hit_Bill++ ;
							}
                            sendbackData(IDs, infoIDs, to_sub_FID, (*cache_iter)) ;
                            if(ebf != ibf)
                            {
                                WritablePacket* packet = p->uniqueify() ;
                                memcpy(packet->data()+14+FID_LEN+sizeof(type)+sizeof(numberOfIDs)+index, ebf.data._data, EBFSIZE) ;
                                output(5).push(packet) ;
                            }
                            return ;
                        }
                    }
                }
                output(5).push(p) ;
            }
            default:
                break ;
        }
    }
}
void CacheUnit::sendbackData(Vector<String>& SIDs, Vector<String>& IIDs, BABitvector FID, CacheEntry* ce)
{
    int reverse_proto ;
    int prototype ;
    cp_integer(String("0x080d"), 16, &reverse_proto);
    prototype = htons(reverse_proto);
    Vector<String> IDs ;
    for(Vector<String>::iterator iid_iter = IIDs.begin() ; iid_iter != IIDs.end() ; iid_iter++)
    {
        IDs.clear() ;
        for(Vector<String>::iterator sid_iter = SIDs.begin() ; sid_iter != SIDs.end() ; sid_iter++)
        {
            String tempstr = (*sid_iter)+(*iid_iter) ;
            IDs.push_back(tempstr) ;
        }
        WritablePacket* packet ;
        int total_ID_length = 0 ;
        unsigned char NOofID = IDs.size() ;
        int IDindex = 0 ;
        unsigned char IDLength /*in fragments*/ ;
        for(Vector<String>::iterator id_iter = IDs.begin() ; id_iter != IDs.end() ; id_iter++)
        {
            total_ID_length += id_iter->length() ;
        }
        unsigned int packet_len = 14+FID_LEN/*reverse FID*/+sizeof(NOofID)/*numberofID*/+NOofID*sizeof(IDLength)/*number of fragment*/+\
                     total_ID_length/*IDs*/+ce->_data_length[*iid_iter] ;
        packet = Packet::make(packet_len) ;
        memcpy(packet->data()+12, &prototype, 2) ;
        memcpy(packet->data()+14, FID._data, FID_LEN) ;
        memcpy(packet->data()+14+FID_LEN, &NOofID, sizeof(NOofID)) ;//#ofID

        for(Vector<String>::iterator id_iter = IDs.begin() ; id_iter != IDs.end() ;id_iter++)//ID length ID
        {
            IDLength = id_iter->length()/PURSUIT_ID_LEN ;
            memcpy(packet->data()+14+FID_LEN+sizeof(NOofID)+IDindex, &IDLength, sizeof(IDLength)) ;
            memcpy(packet->data()+14+FID_LEN+sizeof(NOofID)+IDindex+sizeof(IDLength), id_iter->c_str(),id_iter->length()) ;
            IDindex += sizeof(IDLength)+id_iter->length() ;
        }
        memcpy(packet->data()+14+FID_LEN+sizeof(NOofID)+IDindex, ce->_data[*iid_iter],\
               ce->_data_length[*iid_iter]) ;
        output(1).push(packet) ;
    }
}

void CacheUnit::storecache(Vector<String>& IDs, char* data, unsigned int datalen)
{
    Vector<String>::iterator id_iter ;
    Vector<CacheEntry*>::iterator cache_iter ;
    Vector<String>::iterator local_iid_iter ;
    Vector<String> newSID ;
    bool cacheupdate = false ;
    String IID ;
    IID = IDs[0].substring(IDs[0].length()-PURSUIT_ID_LEN, PURSUIT_ID_LEN) ;
    for(id_iter = IDs.begin() ; id_iter != IDs.end() ; id_iter++)
    {
         newSID.push_back((*id_iter).substring(0, (*id_iter).length()-PURSUIT_ID_LEN)) ;
    }
    for(id_iter = newSID.begin() ; id_iter != newSID.end() ; id_iter++)
    {
        for(cache_iter = cache.begin() ; cache_iter != cache.end() ; cache_iter++)
        {
            if((*cache_iter)->matchSID(*id_iter))
            {
                for(local_iid_iter = (*cache_iter)->IIDs.begin() ; local_iid_iter != (*cache_iter)->IIDs.end() ;local_iid_iter++)
                {
                    if(!IID.compare(*local_iid_iter))
                    {
                        cacheupdate = true ;
                        free(data) ;
                        break ;
                    }
                }
                if(!cacheupdate)
                {
                    (*cache_iter)->IIDs.push_back(IID) ;
                    (*cache_iter)->_data.set(IID, data) ;
                    (*cache_iter)->_data_length.set(IID, datalen) ;
                    (*cache_iter)->total_len += datalen ;
                    current_size += datalen ;
                    cacheupdate = true ;
                }
                (*cache_iter)->SIDs = newSID ;
                break ;
            }
        }
        if(cacheupdate)
            break ;
    }
    if(!cacheupdate)
    {
        CacheEntry* newentry = new CacheEntry(newSID, IID, data, datalen) ;
        cache.push_back(newentry) ;
        current_size += datalen ;
    }
    click_chatter("cache_size:%d current_cache_size:%d", cache_size, current_size) ;
	if(current_size > cache_size)
	{
		click_chatter("cache full flush") ;
		cache_replace++ ;
		if(cache_replace == Billion)
		{
			cache_replace = 0 ;
			cache_replace_Bill++ ;
		}
		CacheEntry* ce = cache[0] ;
		click_chatter("current num of cache:%d", cache.size()) ;
		current_size = current_size - cache[0]->total_len ;
		cache.erase(cache.begin()) ;
		delete ce ;
	}
}

CLICK_ENDDECLS
EXPORT_ELEMENT(CacheUnit)
ELEMENT_REQUIRES(userlevel)
ELEMENT_PROVIDES(CacheEntry)
