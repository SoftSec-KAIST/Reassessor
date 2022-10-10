#include <stdio.h>
int output;
const int bar[]={-0xd0,-0xe0,-0xf0,-0x100};

void foo(int input){
  switch(input){
    case 0:  output = bar[0]; break;
    case 1:  output = bar[1]; break;
    case 2:  output = bar[2]; break;
    case 3:  output = bar[3]; break;
    default: break;
  }
}
int main()
{
    int i;
    foo(i);
    for (i=0; i < 4; ++i){
        foo(i);
        printf("Hello World [In:%d, Out:%d]\n", i, output);
    }
    return 0;
}
