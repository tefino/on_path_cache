#ifndef BLOOMFILTER_HH_INCLUDED
#define BLOOMFILTER_HH_INCLUDED

#include "ba_bitvector.hh"
#include <click/string.hh>
#include <click/hashtable.hh>

CLICK_DECLS
class BloomFilter
{
public:
    BloomFilter(): len_in_bytes(0), len_in_bits(0) {
        BABitvector temp(0)  ;
        data = temp ;
    }
    BloomFilter(int length)
    {
        data.assign(length, false) ;
        len_in_bytes = length/8 ;
        len_in_bits = length ;
    }
    ~BloomFilter(){}
    inline void zero()
    {
        data.zero() ;
    }
    inline void add2bf(String str)
    {
        BABitvector temp((int)len_in_bytes*8) ;
        memcpy(temp._data, str.c_str(), len_in_bytes) ;
        data = data | temp ;
    }
    bool test(String str)
    {
        BABitvector temp((int)len_in_bytes*8) ;
        memcpy(temp._data, str.c_str(), len_in_bytes) ;
        BABitvector test((int)len_in_bytes*8) ;
        test = temp & data ;
        if(test == temp)
            return true ;
        else
            return false ;
    }
    inline void resize(int bits)
    {
        data.resize(bits) ;
        len_in_bits = bits ;
        len_in_bytes = bits/8 ;
    }
    bool operator==(const BloomFilter &x) const {
        return data == x.data ;
    }
    bool operator!=(const BloomFilter &x) const {
        return !(data == x.data) ;
    }
    BABitvector data ;
    unsigned int len_in_bytes ;
    unsigned int len_in_bits ;
};
CLICK_ENDDECLS
#endif // BLOOMFILTER_HH_INCLUDED
