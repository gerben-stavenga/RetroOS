#ifndef BASIC_H
#define BASIC_H

#include "src/kernel/pipe.h"

extern PipeN<1024> key_pipe;

int GetTime();

void TimerHandler();
void ProcessKey(int key);

#endif  // BASIC_H