/* Check if finding multiple signatures for a method is handled gracefully.  */
/* Author:  Ziemowit Laski <zlaski@apple.com>  */
/* { dg-do compile } */
/* { dg-options "-Wstrict-selector-match" } */

#include <objc/objc.h>
#include "../objc-obj-c++-shared/TestsuiteObject.h"

@interface Class1
- (void)setWindow:(TestsuiteObject *)wdw;
@end

@interface Class2
- (void)setWindow:(Class1 *)window;
@end

id foo(void) {
  TestsuiteObject *obj = [[TestsuiteObject alloc] init];
  id obj2 = obj;
  [obj setWindow:nil];  /* { dg-warning ".TestsuiteObject. may not respond to .\\-setWindow:." } */
  /* { dg-warning "Messages without a matching method signature" "" { target *-*-* } 20 } */
  /* { dg-warning "will be assumed to return .id. and accept" "" { target *-*-* } 20 } */
  /* { dg-warning ".\.\.\.. as arguments" "" { target *-*-* } 20 } */
  [obj2 setWindow:nil]; /* { dg-warning "multiple methods named .\\-setWindow:. found" } */
  /* { dg-message "using .\\-\\(void\\)setWindow:\\(TestsuiteObject \\*\\)wdw." "" { target *-*-* } 10 } */
  /* { dg-message "also found .\\-\\(void\\)setWindow:\\(Class1 \\*\\)window." "" { target *-*-* } 14 } */

  return obj;
}
