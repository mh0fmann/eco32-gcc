
// DO NOT EDIT THIS FILE - it is machine generated -*- c++ -*-

#ifndef __javax_security_auth_AuthPermission__
#define __javax_security_auth_AuthPermission__

#pragma interface

#include <java/security/BasicPermission.h>
extern "Java"
{
  namespace javax
  {
    namespace security
    {
      namespace auth
      {
          class AuthPermission;
      }
    }
  }
}

class javax::security::auth::AuthPermission : public ::java::security::BasicPermission
{

public:
  AuthPermission(::java::lang::String *);
  AuthPermission(::java::lang::String *, ::java::lang::String *);
  static ::java::lang::Class class$;
};

#endif // __javax_security_auth_AuthPermission__
