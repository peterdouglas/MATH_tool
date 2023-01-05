![MATH - Modified Algorand Tealer Helper](MATH.png)
***
MATH is static analyzer for [Teal](https://developer.algorand.org/docs/features/asc1/) code. It parses the Teal program, and builds its CFG. This project has been built on top of the great work by Crytic on (Tealer)[https://github.com/crytic/tealer].

This tool is a part of the unpublished paper *MATH - Finding and Fixing Exploits on Algorand*, and runs two detectors by default.

- [Features](#features)
  - [Detectors](#detectors)
  - [Printers](#printers)
- [How to install](#how-to-install)
- [How to run](#how-to-run)
  - [Example](#example)

## Features
### Detectors
 Num |   Check   |               What it Detects                |      Type
--- | --- | --- | ---
  1  | bSubtract | Detect instances of the byte subtraction vulnerability |    Stateful
  2  | mathploit | Detect instances of the math exploit |    Stateful


All the detectors are run by default

### Printers
- Print CFG (`--print-cfg`)

Printers output [`dot`](https://graphviz.org/) files.
Use `xdot` to open the files  (`sudo apt install xdot`).

## How to install
Run
```bash
python3 setup.py install
```

We recommend to install the tool in a [virtualenv](https://virtualenvwrapper.readthedocs.io/en/latest/).

## How to run
```bash
tealer code.teal
```

### Example
The following shows the CFG from [algorand/smart-contracts](https://github.com/algorand/smart-contracts.git).
```bash
git clone https://github.com/algorand/smart-contracts.git
cd smart-contracts
tealer ./devrel/permission-less-voting/vote_opt_out.teal --print-cfg
```

<img src="./examples/vote_opt_out.png" alt="Example" width="500"/>

