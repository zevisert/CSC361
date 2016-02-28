TCP Capture File Parser
Author: Zev Isert
CSC361 - Assignment 2

-----------------------------------
Building
-----------------------------------

- use make
    - all
    - remake
    - clean

- All build files in current directory

-----------------------------------
Running
-----------------------------------

- make compiles to ./traceParse
    - quick usage:
        ./traceParse <List of .cap files to process>

-----------------------------------
Discrepencies
-----------------------------------

- Because a connection can be reset after its has completed,
  it may print extended information despite being in the R state

	- To show the state a connection was in before the reset,
	  recompile with ./TraceParse.c/SHOW_RESET_PROIR_STATE defined as
	  true. The define preprocessor statementent can be found at the
	  top of the file.

- Connections that were completed then reset are still counted towards
  the totals reported for the file.

- Duration may be reported in various ways. For the purposes of this assignment,
  duration is calculated relative to the first packet in the capture file. The 
  "timersub" macro in ./TraceParse.h calculates the difference in two timeval
  structs, accounting for microsecond overflow.

