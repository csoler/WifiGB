#pragma once

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <openssl/rand.h>
#include "hex.h"
#include "radix64.h"

class MemBlock: public std::vector<unsigned char>
{
	public:
		MemBlock() {}

		MemBlock(const unsigned char *mem,uint32_t size) : std::vector<unsigned char>(size)
		{
			memcpy(data(),mem,size) ;
		}

		MemBlock(uint32_t size,unsigned char val=0) : std::vector<unsigned char>(size,val)
		{
		}

		bool operator==(const MemBlock& mem) const
		{
			return mem.size() == size() && !memcmp(data(),mem.data(),size()) ;
		}

		MemBlock subblock(int offset,int chunk_size) const
		{
			assert(offset < size()) ;
			assert(offset >= 0) ;
			assert(offset+chunk_size <= size()) ;
			assert(offset+chunk_size >= 0) ;

			return MemBlock(data()+offset,chunk_size) ;
		}

		bool isSubBlock(const MemBlock& m) const
		{
			if(m.size() < size())
				return false ;

			for(uint32_t i=0;i+size()<=m.size();++i)	// for all positions into m
			{
				bool equal = true ;

				for(uint32_t j=0;j<size();++j)
					if(operator[](j) != m[i+j])
					{
						equal=false ;
						break ;
					}

				if(equal)
					return true ;
			}
			return false ;
		}

		static MemBlock fromString(const std::string& string) 
		{
			return MemBlock((unsigned char *)string.c_str(),string.length()) ;
		}
		static MemBlock fromHex(const std::string& hex_string) 
		{
			unsigned char *out ;
			uint32_t len ;

			HexUtil::hex_to_bytes(hex_string,out,len) ;
			MemBlock res(out,len) ;

			delete[] out ;

			return res ;
		}
		static MemBlock fromRadix64(const std::string& radix_string) 
		{
			unsigned char *out;
			size_t len ;

			Radix64::decode(radix_string,out,len) ;

			MemBlock res(out,len) ;
			free(out) ;

			return res ;
		}

		static MemBlock random(int s)
		{
			MemBlock b(s) ;
			RAND_bytes(b.data(),s) ;
			return b ;
		}

		MemBlock operator+(const MemBlock& b) const
		{
			MemBlock res(size()+b.size()) ;
			memcpy(res.data(),data(),size()) ;
			memcpy(res.data()+size(),b.data(),b.size()) ;
			return res ;
		}
		MemBlock& operator+=(const MemBlock& b)
		{
			int old_size = size() ;
			resize(size() + b.size()) ;
			memcpy(data()+old_size,b.data(),b.size()) ;

			return *this ;
		}
		MemBlock operator^(const MemBlock& b) const
		{
			assert(b.size() == size()) ;

			MemBlock res(*this) ;
			HexUtil::repeted_xor_encrypt(res.data(),res.size(),b.data(),size()) ;

			return res ;
		}

		std::string toRadix64() const { std::string s ; Radix64::encode(data(),size(),s) ; return s ; } 
		std::string toHex(int blocksize = 0) const 
		{ 
			std::string res = HexUtil::bytes_to_string(data(),size()) ; 

			if(blocksize > 0)
			{
				std::string res2 ;
				for(int i=0;i<res.length();i+=2*blocksize)
				{
					res2 += res.substr(i,2*blocksize) ;
					if(i < res.length()-1)
						res2 += " " ;
				}
					res = res2 ;
			}
			return res ;
		} 
		std::string toString() const { return std::string((char*)data(),size()) ; }

		unsigned char *bytes() const { return (unsigned char *)data() ; }
};
