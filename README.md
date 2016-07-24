A DES implementation
====================

Usage:
======

        $ des  [-e|-d] -f <file> -k <key>

Key is `8` byte

In the encode mode, the file will be a stream of ASCII characters
i.e, each visible character is read as a byte and the encrypted
text is dumped as hex chars, therefore, in the decode mode, the
file will be read as a stream of hex-chars, i,e each visible char
as a nibble.


Example:
========

   ./des -e -k anitest1 -f adata.dat  > enc.dat
   ./des -d -k anitest1 -f enc.dat


Note:
-----

Variable naming conventions are very awkward - that is
to make it easier to understand when read with [2]

Source files:
==============

`des.c` - is the complete implementation of the encode
          as well as decode, easily read when [2] is referred.

`flblkread.c` - is the file reader to slurp the whole file
                at one go, if the file is too large to be handled
                error may be thrown.

`getopts.c`   - option handler

Tests:
======

Run a simple regression with regress.pl

References:
===========

*Wikipedia*
Main entry and the supplementary material in:
[1] http://en.wikipedia.org/wiki/DES_supplementary_material

*Excellent Description With Example*:
[2] http://orlingrabbe.com/des.htm

[3] http://www.tropsoft.com/strongenc/des.htm
