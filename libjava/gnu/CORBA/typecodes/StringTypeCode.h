
// DO NOT EDIT THIS FILE - it is machine generated -*- c++ -*-

#ifndef __gnu_CORBA_typecodes_StringTypeCode__
#define __gnu_CORBA_typecodes_StringTypeCode__

#pragma interface

#include <gnu/CORBA/typecodes/PrimitiveTypeCode.h>
extern "Java"
{
  namespace gnu
  {
    namespace CORBA
    {
      namespace typecodes
      {
          class StringTypeCode;
      }
    }
  }
  namespace org
  {
    namespace omg
    {
      namespace CORBA
      {
          class TCKind;
      }
    }
  }
}

class gnu::CORBA::typecodes::StringTypeCode : public ::gnu::CORBA::typecodes::PrimitiveTypeCode
{

public:
  StringTypeCode(::org::omg::CORBA::TCKind *);
  virtual void setLength(jint);
  virtual jint length();
private:
  static const jlong serialVersionUID = 1LL;
  jint __attribute__((aligned(__alignof__( ::gnu::CORBA::typecodes::PrimitiveTypeCode)))) len;
public:
  static ::java::lang::Class class$;
};

#endif // __gnu_CORBA_typecodes_StringTypeCode__