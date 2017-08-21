# Daredevil
*His senses function with superhuman accuracy and sensitivity, giving him abilities far beyond the limits of a sighted person*

Daredevil is a tool to perform (higher-order) correlation power analysis attacks (CPA). 
It allows the user to compute CPA attacks on multiple cores given a specified amount 
of memory. The initial release of Daredevil implements the fastest approaches as 
outlined in the paper

Paul Bottinelli and Joppe W. Bos:  
Computational Aspects of Correlation Power Analysis.  
Journal of Cryptographic Engineering (to appear): http://link.springer.com/article/10.1007/s13389-016-0122-9

See also:  
Cryptology ePrint Archive, Report 2015/260, IACR, 2015.  
http://eprint.iacr.org/2015/260.pdf


## Dependencies

This software only requires a compiler with OpenMP support (by default clang).  
E.g. on a Debian/Ubuntu environment, one can do:

```bash
sudo apt-get install --no-install-recommends clang make libomp-dev
```

## Installation

To compile daredevil simply run:

```bash
make
```

To install it simply run:

```bash
sudo make install
```

You can uninstall it with:

```bash
sudo make uninstall
```

You can also specify the compiler with the CC variable as well as an
installation prefix else than the default /usr/local:

```bash
make CC=g++
sudo make install PREFIX=/usr
```

If you've troubles using clang with OpenMP on your distribution, try
using g++ as explained above.
