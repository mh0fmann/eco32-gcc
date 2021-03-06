
// DO NOT EDIT THIS FILE - it is machine generated -*- c++ -*-

#ifndef __gnu_gcj_xlib_Window__
#define __gnu_gcj_xlib_Window__

#pragma interface

#include <gnu/gcj/xlib/Drawable.h>
#include <gcj/array.h>

extern "Java"
{
  namespace gnu
  {
    namespace gcj
    {
      namespace xlib
      {
          class Display;
          class Visual;
          class Window;
          class WindowAttributes;
      }
    }
  }
  namespace java
  {
    namespace awt
    {
        class Rectangle;
    }
  }
}

class gnu::gcj::xlib::Window : public ::gnu::gcj::xlib::Drawable
{

public:
  Window(::gnu::gcj::xlib::Window *, ::java::awt::Rectangle *, ::gnu::gcj::xlib::WindowAttributes *);
  Window(::gnu::gcj::xlib::Window *, ::java::awt::Rectangle *, ::gnu::gcj::xlib::WindowAttributes *, ::gnu::gcj::xlib::Visual *);
  Window(::gnu::gcj::xlib::Window *, ::java::awt::Rectangle *, jint, ::gnu::gcj::xlib::WindowAttributes *, jint, ::gnu::gcj::xlib::Visual *);
public: // actually protected
  Window(::gnu::gcj::xlib::Display *, jint);
  virtual void finalize();
  virtual void destroy();
  virtual jint createChildXID(::java::awt::Rectangle *, jint, ::gnu::gcj::xlib::WindowAttributes *, jint, ::gnu::gcj::xlib::Visual *);
public:
  virtual void setAttributes(::gnu::gcj::xlib::WindowAttributes *);
  virtual void map();
  virtual void unmap();
  virtual void toFront();
  virtual void toBack();
  virtual void setProperty(jint, jint, JArray< jbyte > *);
  virtual void setProperty(jint, jint, ::java::lang::String *);
  virtual void setWMProtocols(JArray< jint > *);
  virtual JArray< jint > * getWMProtocols();
  virtual void setProperty(::java::lang::String *, ::java::lang::String *, ::java::lang::String *);
  virtual void setBounds(jint, jint, jint, jint);
  static const jint COPY_FROM_PARENT = 0;
  static const jint INPUT_OUTPUT = 1;
  static const jint INPUT_ONLY = 2;
public: // actually protected
  jboolean __attribute__((aligned(__alignof__( ::gnu::gcj::xlib::Drawable)))) owned;
public:
  static ::java::lang::Class class$;
};

#endif // __gnu_gcj_xlib_Window__
