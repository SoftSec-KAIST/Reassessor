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
  printf("In:%d, Out:%d\n", input, output);
}
int main()
{
    int i = getchar();
    foo(i);
    return 0;
}
