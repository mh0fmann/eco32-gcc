// DO NOT EDIT THIS FILE - it is machine generated -*- c++ -*-

#ifndef __getallthreads__
#define __getallthreads__

#pragma interface

#include <java/lang/Thread.h>
#include <gcj/array.h>

extern "Java"
{
  class getallthreads;
}

class getallthreads : public ::java::lang::Thread
{
public:
  getallthreads ();
  static void do_getallthreads_tests ();
  virtual void run ();
  virtual void natPlaceholder ();
  virtual void natRunner ();
  virtual void placeholder ();
  virtual void runner ();
  static void main (JArray< ::java::lang::String *> *);
  static jint thread_num;
  static ::java::util::ArrayList *threads;
  jint __attribute__((aligned(__alignof__( ::java::lang::Thread ))))  ex_frames;
  jboolean done;

  static ::java::lang::Class class$;
};

#endif /* __getallthreads__ */