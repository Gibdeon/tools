#!/usr/bin/env python
import sys
from pwn import *


bucle = "\xEB\xFE"
e = ELF(sys.argv[1])
main_addr = e.symbols['main']
entry = e.entrypoint



# Imprime direciones
log.info("Entrypoint at: " + hex(entry))
log.info("Main at: " + hex(main_addr))
 
# Desensambla el principio del main
log.info(disasm(e.read(main_addr, 14), arch='x86'))

e.write(entry,bucle)
e.save(sys.argv[1] + "_rep")
dis = e.read(entry,2)
log.info("Bytes in Entrypoint: " + dis.encode("hex"))
