#pragma once

#include <stdint.h>
#include "memblock.h"
#include <openssl/sha.h>

class Sha1CheckSum
{
	public:
	   static const uint32_t HASH_LENGTH = SHA_DIGEST_LENGTH ;

		bool operator<(const Sha1CheckSum& s) const
		{
			for(int i=0;i<HASH_LENGTH;++i)
				if(bytes[i] < s.bytes[i])
					return true ;
				else if(bytes[i] > s.bytes[i])
					return false ;

			return false ;
		}

		explicit Sha1CheckSum(const unsigned char *data,size_t size)
		{
			SHA_CTX sha_ctx ;

			if(HASH_LENGTH != 20) 
				throw std::runtime_error("Warning: can't compute Sha1Sum with sum size != 20") ;

			SHA1_Init(&sha_ctx);
			while(size > 512)
			{
				SHA1_Update(&sha_ctx, data, 512);
				data = &data[512] ;
				size -= 512 ;
			}
			SHA1_Update(&sha_ctx, data, size);
			SHA1_Final(&bytes[0], &sha_ctx);
		}

		std::string toStdString() const
		{
			static const char outl[16] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' } ;

			std::string res(HASH_LENGTH*2,' ') ;

			for(uint32_t j = 0; j < HASH_LENGTH; j++)
			{
				res[2*j  ] = outl[ (bytes[j]>>4) ] ;
				res[2*j+1] = outl[ bytes[j] & 0xf ] ;
			}

			return res ;
		}

		unsigned char bytes[HASH_LENGTH] ;
};

