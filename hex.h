#pragma once

#include <string>
#include <stdexcept>

class HexUtil
{
	public:
		static void hex_to_bytes(const std::string& input,unsigned char *& mem,uint32_t& size)
		{
			mem=NULL ;
			if(input.length()&1 != 0)
				throw std::runtime_error("String should have an even number of hex digits.") ;

			size = (input.length()+1)/2 ;
			mem = new unsigned char[size] ;
			uint32_t n=0 ;

			for(uint32_t i = 0; i < size; ++i)
			{
				mem[i] = 0 ;

				for(int k=0;k<2;++k)
				{
					char b = input[n++] ;

					if(b >= 'A' && b <= 'F')
						mem[i] += (b-'A'+10) << 4*(1-k) ;
					else if(b >= 'a' && b <= 'f')
						mem[i] += (b-'a'+10) << 4*(1-k) ;
					else if(b >= '0' && b <= '9')
						mem[i] += (b-'0') << 4*(1-k) ;
					else
						throw std::runtime_error("supplied string is not purely hexadecimal") ;
				}
			}

		}

		static std::string bytes_to_string(const unsigned char *mem,uint32_t size,bool upper_case=false)
		{
			static const char outh[16] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' } ;
			static const char outl[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' } ;

			std::string res(size*2,' ') ;

			for(uint32_t j = 0; j < size; j++)
				if(upper_case)
				{
					res[2*j  ] = outh[ (mem[j]>>4) ] ;
					res[2*j+1] = outh[ mem[j] & 0xf ] ;
				}
				else
				{
					res[2*j  ] = outl[ (mem[j]>>4) ] ;
					res[2*j+1] = outl[ mem[j] & 0xf ] ;
				}
			 return res ;
		}

		static void repeted_xor_encrypt(unsigned char *mem,uint32_t size,const unsigned char *key,uint32_t key_size)
		{
			for(int i=0;i<(int)size;++i)
				mem[i] ^= key[i%key_size] ;
		}

		static uint32_t hamming_distance(const unsigned char *mem1,const unsigned char *mem2,uint32_t size)
		{
			uint32_t res = 0 ;

			for(uint32_t i=0;i<size;++i)
				for(int k=0;k<8;++k)
					res += ( (mem1[i] & (1<<k)) != (mem2[i] & (1<<k)) ) ;

			return res ;
		}
};
