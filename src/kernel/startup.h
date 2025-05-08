#ifndef KERNEL_STARTUP_H
#define KERNEL_STARTUP_H

void StackTrace();

[[noreturn]] void Startup(unsigned start_sector, PageTable* page_dir);

#endif  // KERNEL_STARTUP_H
