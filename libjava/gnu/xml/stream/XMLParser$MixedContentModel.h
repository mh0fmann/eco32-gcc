
// DO NOT EDIT THIS FILE - it is machine generated -*- c++ -*-

#ifndef __gnu_xml_stream_XMLParser$MixedContentModel__
#define __gnu_xml_stream_XMLParser$MixedContentModel__

#pragma interface

#include <gnu/xml/stream/XMLParser$ContentModel.h>
extern "Java"
{
  namespace gnu
  {
    namespace xml
    {
      namespace stream
      {
          class XMLParser;
          class XMLParser$MixedContentModel;
      }
    }
  }
}

class gnu::xml::stream::XMLParser$MixedContentModel : public ::gnu::xml::stream::XMLParser$ContentModel
{

public: // actually package-private
  XMLParser$MixedContentModel(::gnu::xml::stream::XMLParser *);
  virtual void addName(::java::lang::String *);
  virtual jboolean containsName(::java::lang::String *);
private:
  ::java::util::HashSet * __attribute__((aligned(__alignof__( ::gnu::xml::stream::XMLParser$ContentModel)))) names;
public: // actually package-private
  ::gnu::xml::stream::XMLParser * this$0;
public:
  static ::java::lang::Class class$;
};

#endif // __gnu_xml_stream_XMLParser$MixedContentModel__