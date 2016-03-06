// COMPILE_LINE: g++ -g main.cpp -o wifigb -lstdc++ -lssl -lcrypto
//
#include <iostream>
#include <queue>
#include <set>
#include <stdexcept>

#include "Config.h"
#include "sha1hash.h"
#include "memblock.h"
#include "argstream.h"

#include <openssl/evp.h>

class Expression
{
	public:
		virtual ~Expression() {}

		virtual float entropy() const = 0 ; // maximum entropy of the whole expression in bits
		virtual MemBlock eval() const = 0 ;	// evaluates the expression and produces a stream of bytes.
		virtual int length() 	const = 0 ;	// evaluates the expression and produces a stream of bytes.

		void show() const { print(0) ; std::cerr << std::endl; }

		virtual void initState() = 0;					// get to next state. Returns false if not possible.
		virtual bool nextState() = 0;					// get to next state. Returns false if not possible.
		virtual Expression *deepCopy() const=0 ;

		virtual Sha1CheckSum topologicalHash() = 0 ;	// computes the hash so as to be able to check the equality
		virtual void print(int depth) const =0 ;     // hierarchical display
	protected:

		friend class Exp_substring ;
};
class Exp_const: public Expression
{
	public:
		virtual ~Exp_const() {}

		Exp_const(const MemBlock& mem) : mMem(mem) {}

		virtual float entropy() const { return mMem.size()*8 ; }
		virtual MemBlock eval() const { return mMem ; }
		virtual int length() 	const { mMem.size() ; }

		virtual void initState() {}	// nothing to do.
		virtual bool nextState() { return false ; } // no parameters, so nothing to do.
		
		virtual Expression *deepCopy() const{ return new Exp_const(*this) ; }

		virtual Sha1CheckSum topologicalHash() { return Sha1CheckSum((unsigned char*)mMem.toString().c_str(),mMem.size()) ; }
	protected:
		virtual void print(int depth) const 
		{
			for(int i=0;i<depth*2;++i) std::cerr << " " ; 
			std::cerr << "Const: " << mMem.toHex() << std::endl;
		}

		MemBlock mMem ;
};
class Exp_numeric_counter: public Expression
{
	public:
		virtual ~Exp_numeric_counter() {}

		Exp_numeric_counter(uint8_t bytes) : mBytes(bytes),mValue(0) {}

		virtual float entropy() const { return mBytes*8 ; }
		virtual MemBlock eval() const { MemBlock mem(mBytes,0) ; for(int i=0;i<mBytes;++i) mem[i] = ((mValue >> (8*i)) & 0xff) ; return mem ;}
		virtual int length() 	const { return mBytes ; }

		virtual void initState() { mValue = 0 ;}	// nothing to do.
		virtual bool nextState() { return ++mValue < (1ull << (mBytes*8)) ; } // no parameters, so nothing to do.
		
		virtual Expression *deepCopy() const{ return new Exp_numeric_counter(*this) ; }

		virtual Sha1CheckSum topologicalHash() { std::string s = "Numeric counter" ; return Sha1CheckSum((unsigned char*)s.c_str(),s.length()) ; }
	protected:
		virtual void print(int depth) const 
		{
			for(int i=0;i<depth*2;++i) std::cerr << " " ; 
			std::cerr << "Counter: " << eval().toHex() << std::endl;
		}

		uint64_t mValue ;
		uint8_t mBytes ;
};
class Exp_ascii_counter: public Expression
{
	public:
		virtual ~Exp_ascii_counter() {}

		Exp_ascii_counter(uint8_t bytes,char base) : mBytes(bytes),mBase(base),mValues(bytes,0) {}

		virtual float entropy() const { return mBytes*8 ; }
		virtual MemBlock eval() const { MemBlock mem(mBytes,0) ; for(int i=0;i<mBytes;++i) mem[i] = mValues[i] + mBase ; return mem ;}
		virtual int length() 	const { return mBytes ; }

		virtual void initState() { mValues.clear(); mValues.resize(mBytes,0) ;}	// nothing to do.

		virtual bool nextState() 
		{ 
			for(int i=0;i<mBytes;++i)
				if(++mValues[i] < 26)
					return true ;
				else
					mValues[i] = 0 ;

			return false ;
		} // no parameters, so nothing to do.
		
		virtual Expression *deepCopy() const{ return new Exp_ascii_counter(*this) ; }

		virtual Sha1CheckSum topologicalHash() { std::string s = "ASCII"+mBase+('A'+mBytes) ; return Sha1CheckSum((unsigned char*)s.c_str(),s.length()) ; }
	protected:
		virtual void print(int depth) const 
		{
			for(int i=0;i<depth*2;++i) std::cerr << " " ; 
			std::cerr << "Ascii Counter: " << eval().toString() << std::endl;
		}

		std::vector<uint8_t> mValues ;
		uint8_t mBytes ;
		char mBase ;
};
class Exp_hash_sha1: public Expression
{
	public:
		Exp_hash_sha1(Expression *e)
		{
			mArgument = e ;
		}
		virtual ~Exp_hash_sha1() { delete mArgument ; } 
		virtual Expression *deepCopy() const{ return new Exp_hash_sha1(mArgument->deepCopy()) ; }

		virtual Sha1CheckSum topologicalHash() 
		{ 
			std::string s = "sha1hash" + mArgument->topologicalHash().toStdString() ;
			return Sha1CheckSum((unsigned char*)s.c_str(),s.length()) ;
		}

	protected:
		virtual void print(int depth) const 
		{
			for(int i=0;i<depth*2;++i) std::cerr << " " ; 
			std::cerr << "SHA1()" << std::endl;

			mArgument->print(depth+1) ;
		}
		virtual float entropy() const 
		{
			return 1+mArgument->entropy();
		}
		virtual MemBlock eval() const 
		{
			MemBlock m = mArgument->eval() ;
			return MemBlock(Sha1CheckSum(m.data(),m.size()).bytes,Sha1CheckSum::HASH_LENGTH) ;
		}

		virtual int length() const { return Sha1CheckSum::HASH_LENGTH ; }

		virtual void initState() {}
		virtual bool nextState() 
		{ 
			return false ;
		}
		
	private:
		Expression *mArgument ;
};

class Exp_hash_generic: public Expression
{
	public:
		Exp_hash_generic(Expression *e)
		{
			mArgument = e ;
			mHashId= 0;
		}
		virtual ~Exp_hash_generic() { delete mArgument ; }
		virtual Expression *deepCopy() const { return new Exp_hash_generic(mArgument->deepCopy()) ; }

		virtual void initState() { mHashId = 0 ;}
		virtual bool nextState() 
		{ 
			if(mArgument->nextState())
				return true ;

			mArgument->initState() ;

			mHashId = (mHashId+1)%mNumHashes; 
			return (bool)mHashId; 
		}
		virtual float entropy() const { return mArgument->entropy() + 1; }

		virtual Sha1CheckSum topologicalHash() 
		{ 
			std::string s = digest_names[mHashId] + mArgument->topologicalHash().toStdString() ;
			return Sha1CheckSum((unsigned char*)s.c_str(),s.length()) ;
		}
		virtual MemBlock eval() const 
		{
			MemBlock m = mArgument->eval() ;
			unsigned int md_len ;

			EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

			unsigned char md_value[EVP_MAX_MD_SIZE];

        EVP_DigestInit_ex(mdctx, digests[mHashId], NULL);

        EVP_DigestUpdate(mdctx, m.bytes(), m.size());
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);

        EVP_MD_CTX_destroy(mdctx);

			return MemBlock(md_value,md_len) ;
		}

		virtual int length() const { return EVP_MD_size(digests[mHashId]) ; }

		virtual void print(int depth) const 
		{
			for(int i=0;i<depth*2;++i) std::cerr << " " ; 
			std::cerr << digest_names[mHashId] << "()" << std::endl;

			mArgument->print(depth+1) ;
		}
	
	private:
		static const EVP_MD *digests[10] ;
		static const std::string digest_names[10] ;
		static const int mNumHashes = 10 ;

		uint32_t mHashId ;
		Expression *mArgument;
};

const EVP_MD *Exp_hash_generic::digests[10]          = { EVP_whirlpool(), EVP_md5(), EVP_sha(), EVP_sha224(),EVP_sha1(), EVP_sha384(), EVP_sha256(), EVP_sha512(),EVP_md4(), EVP_ripemd160() } ;
const std::string Exp_hash_generic::digest_names[10] = { "whirlpool","md5","sha","sha224","sha1","sha384", "sha256", "sha512","md4","ripemd160" } ;

class Exp_substring: public Expression
{
	public:
		Exp_substring(Expression *e,int min_length=1,int max_length=0) 
			: mMinLength(min_length),mMaxLength(max_length)
		{
			mArgument = e ;
			mStart = 0 ;
			mLength = min_length ;
		}
		virtual ~Exp_substring() { delete mArgument ; } 

		virtual Expression *deepCopy() const{ return new Exp_substring(mArgument->deepCopy()) ; }

		virtual Sha1CheckSum topologicalHash() 
		{ 
			std::string s = "substring" + mArgument->topologicalHash().toStdString() ;

			return Sha1CheckSum((unsigned char*)s.c_str(),s.length()) ;
		}

	protected:
		virtual void print(int depth) const 
		{
			for(int i=0;i<depth*2;++i) std::cerr << " " ; 
			std::cerr << "Substring(" << mStart << "," << mLength << ")" << std::endl;

			mArgument->print(depth+1) ;
		}
		virtual float entropy() const 
		{
			return 8*mMaxLength ;
		}
		virtual MemBlock eval() const 
		{
			MemBlock m = mArgument->eval() ;
			return m.subblock(mStart,mLength) ;
		}

		virtual int length() const { return mLength ; }

		virtual void initState() { mArgument->initState() ; mStart=0; mLength=mMinLength ;}	
		virtual bool nextState() 
		{ 
			if(mStart+mLength < mArgument->length() && (mMaxLength==0 || mLength < mMaxLength))
			{
				++mLength ;
				return true ;
			}
			else if(mStart < mArgument->length() - 1 - mMinLength)
			{
				mLength=mMinLength ;
				++mStart ;
				return true ;
			}
			else
			{
				mLength = mMinLength ;
				mStart = 0 ;

				return mArgument->nextState() ;
			}
		} 
		
	private:
		int mStart ;	// parameter 1
		int mLength ;	// parameter 2

		int mMinLength ;
		int mMaxLength ;

		Expression *mArgument ;
};
class Exp_concat: public Expression
{
	public:
		Exp_concat(Expression *e1,Expression *e2)
		{
			mArgument1 = e1 ;
			mArgument2 = e2 ;
		}
		virtual ~Exp_concat() { delete mArgument1; delete mArgument2 ; } 
		virtual Expression *deepCopy() const{ return new Exp_concat(mArgument1->deepCopy(),mArgument2->deepCopy()) ; }

		virtual Sha1CheckSum topologicalHash() 
		{ 
			std::string s = "concat" + mArgument1->topologicalHash().toStdString() + mArgument2->topologicalHash().toStdString() ;
			return Sha1CheckSum((unsigned char*)s.c_str(),s.length()) ;
		}

	protected:
		virtual void print(int depth) const 
		{
			for(int i=0;i<depth*2;++i) std::cerr << " " ; 
			std::cerr << "Concat()" << std::endl;

			mArgument1->print(depth+1) ;
			mArgument2->print(depth+1) ;
		}
		virtual float entropy() const 
		{
			return 1 + mArgument1->entropy() + mArgument2->entropy() ;
		}
		virtual MemBlock eval() const 
		{
			MemBlock m1 = mArgument1->eval() ;
			MemBlock m2 = mArgument2->eval() ;

			return m1+m2 ;
		}

		virtual int length() const { return mArgument1->length() + mArgument2->length() ; }

		virtual void initState() { mArgument1->initState(); mArgument2->initState(); }
		virtual bool nextState() 
		{ 
			if(mArgument1->nextState())
				return true ;

			mArgument1->initState() ;

			return mArgument2->nextState() ;
		} 
		
	private:
		Expression *mArgument1 ;
		Expression *mArgument2 ;
};
static bool MemBlockMatch(const MemBlock& input_hex,const MemBlock& b)
{
	if( input_hex == b)
		return true;

	if(b.size() < input_hex.size())
		return false ;

	if(input_hex.isSubBlock(b))
		return true ;

	return false ;
}

typedef std::pair<float,Expression*> QueueItem ;

bool operator<(const QueueItem& e1,const QueueItem& e2)
{
	return e1.first < e2.first ;
}

typedef std::map<Sha1CheckSum,Expression *> ExpressionQueue;

static bool push_into_queue(ExpressionQueue& queue,Expression *e)
{
	if(queue.find(e->topologicalHash()) != queue.end())
	{
		delete e ;
		return false ;
	}
	queue[e->topologicalHash()] = e ;
	return true ;
}

Expression *random_select_from_queue(const ExpressionQueue& q)
{
	if(q.empty())
		return NULL ;

	uint32_t n = lrand48()%q.size() ;

	ExpressionQueue::const_iterator it(q.begin()) ;
	for(int i=0;i<n;++i)
		++it ;

	return it->second;
}
bool remove_from_queue(ExpressionQueue& q,Expression *e)
{
	ExpressionQueue::iterator it = q.find(e->topologicalHash()) ;

	if(q.end() == it)
		return false ;

	q.erase(it) ;
	return true ;
}

static bool grosbelu(const std::string& input,Expression *& exp,uint64_t& tries)
{
	// read config file.
	//
	Config conf(input.c_str()) ;

	std::vector<std::string> hexa_strings = conf.getMultipleStringValue("HEXA_STRINGS",std::vector<std::string>()) ;
	std::vector<std::string> ascii_strings = conf.getMultipleStringValue("ASCII_STRINGS",std::vector<std::string>()) ;

	std::string hexa_passphrase_string = conf.getStringValue("HEXA_WPA_PASSPHRASE","") ;
	
	if(hexa_passphrase_string.empty())
		throw std::runtime_error("No passphrase hexa string supplied. Please use variable HEXA_WPA_PASSPHRASE in your config file.") ;

	// init queue
	//
	ExpressionQueue queue ;
	tries = 0 ;

	MemBlock input_hex = MemBlock::fromHex(hexa_passphrase_string) ;
	std::set<Sha1CheckSum> queue_content ;

	// 1 - fill the priority queue with some elements, until enough of them, possibly combining them together.

	// push some stuff into the queue
	
	for(uint32_t i=0;i<hexa_strings.size();++i)
	{
		std::cerr << "Adding hexadecimal constant \"" << hexa_strings[i] << "\"" << std::endl;
		push_into_queue(queue,new Exp_const(MemBlock::fromHex(hexa_strings[i]))) ;	   
	}

	for(uint32_t i=0;i<ascii_strings.size();++i)
	{
		std::cerr << "Adding ascii constant \"" << ascii_strings[i] << "\"" << std::endl;
		push_into_queue(queue,new Exp_const(MemBlock::fromString(ascii_strings[i]))) ;	   
	}

	// add a 2 bytes counter

	push_into_queue(queue,new Exp_numeric_counter(4)) ;
	push_into_queue(queue,new Exp_hash_generic(new Exp_ascii_counter(4,'a'))) ;
	push_into_queue(queue,new Exp_ascii_counter(4,'A')) ;
	
	// add a date counter

	//push_into_queue(queue,new Exp_date(2)) ;

	for(int i=0;i<50;++i)
	{
		// take queue content with least entropy and combine them together

		Expression *elem1 = random_select_from_queue(queue) ;

		if(dynamic_cast<Exp_substring*>(elem1) == NULL) push_into_queue(queue,new Exp_substring(elem1->deepCopy())) ;

		push_into_queue(queue,new Exp_hash_generic(elem1->deepCopy())) ;	// could be hash(hash(...)), so no check necessary

		Expression *elem2 = random_select_from_queue(queue) ;

		push_into_queue(queue,new Exp_concat(elem1->deepCopy(),elem2->deepCopy())) ;
	}

	// remove all combinations that are substrings, since we test them as a postpone match
	
	for(ExpressionQueue::iterator it(queue.begin());it!=queue.end();)
		if(dynamic_cast<Exp_substring*>(it->second) != NULL)
		{
			ExpressionQueue::iterator tmp(it) ;
			++tmp;
			delete it->second ;
			queue.erase(it) ;
			it=tmp;

			std::cerr << "Removed one expression that is a top substr" <<std::endl;
		}
		else
			++it ;

	// init all expressions that depend on parameters
	//
	std::cerr << "Input queue:" << std::endl;

	for(ExpressionQueue::iterator it(queue.begin());it!=queue.end();++it)
	{
		std::cerr << "Queue element: " << std::endl;
		it->second->initState() ;
		it->second->show() ;
	}
	std::cerr << "************* END ***********" << std::endl;

	// 2 - take al elements and apply parameters to them, see what we get.
	
	while(!queue.empty())
	{
		Expression *e = random_select_from_queue(queue) ;

		// use new parameter values.
		//

		int i=0 ;

		for(;i<100;++i)
		{
			MemBlock b = e->eval() ;

			//std::cerr << e->length() << std::endl;
		if(drand48() < 0.00001)
			{
				std::cerr << "Testing " << input_hex.toHex() << " toward " << b.toHex() << std::endl;
				e->show();
			}

			if(MemBlockMatch(input_hex,b))
			{
				std::cerr << "matched " << input_hex.toHex() << " with " << b.toHex() << std::endl;
				exp = e ;
				return true ;
			}

			++tries ;
			if(!e->nextState()) 
			{
				remove_from_queue(queue,e) ;
				delete e ;
				std::cerr << "Poped expression out of the queue. Queue size now =" << queue.size() << std::endl;
				break ;
			}
		}
	}
	
	exp=NULL ;

	return false ;
}

int main(int argc,char *argv[])
{
	try
	{
		argstream as(argc,argv) ;

		std::string config_file = "example.cfg" ;

		as >> parameter('i',"config",config_file,"config file to work on",true)
			>> help() ;

		as.defaultErrorHandling() ;

		OpenSSL_add_all_digests() ;

		Expression *exp_found ;
		uint64_t tries; 

		if(grosbelu(config_file,exp_found,tries))
		{
			std::cerr << "Found! Expression is: " << std::endl;
			
			exp_found->show() ;
		}
		else
			std::cerr << "Nothing found, sorry. Number of expressions tested: " << tries << std::endl;

		return 0 ;
	}
	catch(std::exception& e)
	{
		std::cerr << "Exception never handled: " << e.what() << std::endl;
		return 1 ;
	}
}

