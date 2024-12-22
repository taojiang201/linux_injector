all: lurker  saruman parasite parasite_so.so bkdoor mkbin bkdoor_so.so
lurker: lurker.o  osis_tools.o osis_FileMmap.o   SCS.o osis_parasite.o osis_elf.o \
osis_ptrace.o boot_trap.o dlopen_mode.o mclone.o
	g++ -std=c++11 -g lurker.o osis_tools.o osis_FileMmap.o   SCS.o osis_parasite.o \
	osis_elf.o osis_ptrace.o boot_trap.o dlopen_mode.o mclone.o -lstdc++  -o lurker
lurker.o: lurker.cpp
	gcc -std=c++11 -DDEBUG -g -c lurker.cpp
osis_tools.o:osis_tools.cpp
	g++ -std=c++11 -g -w -o osis_tools.o -c osis_tools.cpp
SCS.o:SCS.cpp
	g++ -std=c++11 -g -w -o SCS.o -c SCS.cpp
osis_FileMmap.o : osis_FileMmap.cpp
	g++ -std=c++11 -g -w -o osis_FileMmap.o -c osis_FileMmap.cpp
osis_parasite.o:osis_parasite.cpp
	g++ -std=c++11 -g -w -o osis_parasite.o -c osis_parasite.cpp
osis_elf.o::osis_elf.cpp
	g++ -std=c++11 -g -w -o osis_elf.o -c osis_elf.cpp 
osis_ptrace.o:osis_ptrace.cpp
	g++ -std=c++11 -g -w -o osis_ptrace.o -c osis_ptrace.cpp
boot_trap.o:boot_trap.s
	as --64 -g ./boot_trap.s -o boot_trap.o
dlopen_mode.o:dlopen_mode.s
	as --64 -g ./dlopen_mode.s -o dlopen_mode.o
mclone.o:mclone.s
	as --64 -g ./mclone.s -o mclone.o
bkdoor:bkdoor.o mkbin 
	ld -m elf_x86_64 bkdoor.o -o bkdoor
	./mkbin bkdoor.o
bkdoor.o:bkdoor.s 
	as --64 -g ./bkdoor.s -o bkdoor.o

clean:
	rm -f *.o lurker saruman parasite  parasite_so.so bkdoor bkdoor_so.so mkbin
saruman:host.c
	gcc -m64 -g -o saruman host.c -lpthread
parasite:
	gcc -m64 -g -fpic -pie -o parasite parasite.c
parasite_so.so:parasit_so.c
	gcc -m64 -g -D_GNU_SOURCE -shared -o parasite_so.so -fPIC parasit_so.c
bkdoor_so.so:bkdoor_so.c
	gcc -m64 -g -D_GNU_SOURCE -shared -o bkdoor_so.so -Wl,--entry=parasite_run_ -fPIC bkdoor_so.c
mkbin:mkbin.cpp
	g++  -m64 -g -o mkbin mkbin.cpp osis_tools.o osis_FileMmap.o   SCS.o osis_elf.o -std=c++11
