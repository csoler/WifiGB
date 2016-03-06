/****************************************************************************

 Copyright (C) 2002-2010 Cyril Soler. All rights reserved.

 This file is part of the HQR (High Quality Rendering) plateform.

 http://artis.imag.fr/~Cyril.Soler/HQR

 This file may be used under the terms of the GNU General Public License 
 versions 2.0 or 3.0 as published by the Free Software Foundation and
 appearing in the LICENSE file included in the packaging of this file.

 This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
 WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

*****************************************************************************/


/*!
  \file  main.C
  \brief The main application.

  \author C.Soler
  \date   2004/01/07
  $Id: Config.h 670 2010-12-08 10:15:16Z csoler $

  \b History:
  \verbatim
  ------------------------------------------------------------------------------
  when        version  who       what
  2004/01/07  1.1      C.Soler   Initial version
  ------------------------------------------------------------------------------
  \endverbatim

  \nosubgrouping
*/

#ifndef CONFIG_H
#define CONFIG_H

#include <iostream>
#include <sstream>
#include <string.h>
#include <string>
#include <vector>
#include <stdexcept>
#include "stdio.h"

//#include "Log.h"

class Config
{
    public:
        /// Constructor. Parses the config file filename and builds a database
        /// of variable names and values.

        Config(const char *filename)
        {
            if(filename == NULL)
                return ;

            FILE *f = fopen(filename,"r");

            if(f == NULL)
                throw std::runtime_error(std::string("Could not open config file ")+filename) ;

            char buff[500];
            int lineno = 0;

            while(fgets(buff,500,f) != NULL)
            {
                lineno++;
                int lp = 0;
                int lq = 0;
                char *p = buff;
                char *q = buff;
                char *p1 = NULL;
                char *p2 = NULL;
                char *r = NULL;
                char *s = NULL ;

                if(strlen(buff) > 499)
                {
                    std::cout << "Line too long skipped (line " << lineno << ") in config file " << filename << std::endl;
                    continue ;
                }

                while((*p == ' ')||(*p == '\t')) p++;
                if(*p == '\n')
                    continue ;

                if(*p == '#')      // skip comment
                    continue ;

                while(*q != '=') if(*q == '\n') goto cont1; else q++;
                r = q-1;
                while((*r == ' ')||(*r == '\t')) r--;
                lp = r - p + 1;
                q++;
                while((*q == ' ')||(*q == '\t')) q++;
                if(*q == '\n') goto cont1;

                s = q + strlen(q) - 1 ;
                while((*s == ' ')||(*s == '\t')||(*s == '\n')) s--;
                lq = s - q + 1;

//					lq = strlen(q) - 1;

                p1 = new char[lp+1];
                p2 = new char[lq+1];

                strncpy(p1,p,lp); p1[lp] = 0;
                strncpy(p2,q,lq); p2[lq] = 0;

                config_elems.push_back(Element(p1,p2));
                continue;

cont1:
                std::ostringstream o ;
                o << "Syntax error in config file " << filename << " line " << lineno << std::endl;

                throw std::runtime_error(o.str()) ;
            }

            fclose(f);

            ListAll() ;
        }

        /// Returns the float value associated to the variable of name name
        /// if anything fails, the returned value is false, else it is true.
        float getFloatValue(const char *name,const float default_value = 0.0) const
        {
            float t;

            for(unsigned int i=0;i<config_elems.size();++i)
                if((!strcmp(config_elems[i].varname,name)) && (sscanf(config_elems[i].value,"%f",&t) == 1))
                    return t;

            return default_value;
        }

        /// Returns the int value associated to the variable of name name
        /// if anything fails, the returned value is false, else it is true.
        int getIntValue(const char *name,const int default_value = 0) const
        {
            int t;

            for(unsigned int i=0;i<config_elems.size();++i)
                if((!strcmp(config_elems[i].varname,name)) && (sscanf(config_elems[i].value,"%d",&t) == 1))
                    return t;

            return default_value;
        }

        /// Returns the string value associated to the variable of name name
        /// if anything fails, the returned value is false, else it is true.
        /// The returned string here should never be deleted.
        const char *getStringValue(const char *name,const char *default_value = NULL) const
        {
            for(unsigned int i=0;i<config_elems.size();++i)
                if((!strcmp(config_elems[i].varname,name)))
                    return config_elems[i].value;

            return default_value;
        }

        std::vector<std::string> getMultipleStringValue(const char *name,const std::vector<std::string> default_v) const
        {
            for(unsigned int i=0;i<config_elems.size();++i)
                if((!strcmp(config_elems[i].varname,name)))
                {
                    std::vector<std::string> vs;
                    std::string obj_str(std::string(config_elems[i].value)+" ") ;

                    while(true)
                    {
                        int lb = obj_str.find_first_not_of(" \t\n",0) ;
                        int le = obj_str.find_first_of(" \t\n",lb) ;

                        if(lb < le)
                        {
                            vs.push_back(obj_str.substr(lb,le-lb)) ;
                            obj_str = obj_str.substr(le+1,obj_str.size()) ;
                        }
                        else
                            break ;
                    }

                    return vs ;
                }

            return default_v ;
        }

        void ListAll() const
        {
            std::cout << "Config variables:" << std::endl;

            for(unsigned int i=0;i<config_elems.size();++i)
                std::cout << config_elems[i].varname << " = '" << config_elems[i].value << "'" << std::endl;
        }

        ~Config()
        {
            for(unsigned int i=0;i<config_elems.size();++i)
            {
                delete[] config_elems[i].varname;
                delete[] config_elems[i].value;
            }
        }

    protected:
        class Element
        {
            public:
                Element()
                {
                    varname = NULL;
                    value = NULL;
                }

                ~Element() {}

                Element(const char *var,const char *val)
                    : value(val),varname(var) {}

                const char *value;
                const char *varname;
        };

        std::vector<Element> config_elems;
};

#endif
