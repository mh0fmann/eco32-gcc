
// DO NOT EDIT THIS FILE - it is machine generated -*- c++ -*-

#ifndef __org_omg_CORBA_portable_ValueBase__
#define __org_omg_CORBA_portable_ValueBase__

#pragma interface

#include <java/lang/Object.h>
#include <gcj/array.h>

extern "Java"
{
  namespace org
  {
    namespace omg
    {
      namespace CORBA
      {
        namespace portable
        {
            class ValueBase;
        }
      }
    }
  }
}

class org::omg::CORBA::portable::ValueBase : public ::java::lang::Object
{

public:
  virtual JArray< ::java::lang::String * > * _truncatable_ids() = 0;
  static ::java::lang::Class class$;
} __attribute__ ((java_interface));

#endif // __org_omg_CORBA_portable_ValueBase__
