#!/usr/local/bin/perl -w

foreach $a (<DATA>)
{
chomp $a;
`echo "$a" > tmpDATA123`;
`./des -e -k anitestx -f tmpDATA123 > tmpENCO123`;
`./des -d -k anitestx -f tmpENCO123 > tmpDECO123`;
$diffout = `diff -B tmpDATA123 tmpDECO123`;
if ($diffout) { print "Fail for \"$a\"\n"; }
else {print "pass\n"; }
unlink("tmpDATA123");
unlink("tmpENCO123");
unlink("tmpDECO123");
}

__DATA__
this is a stupid regression
has some text
in lines
some short
and some very long just to try to confuse the program
but anyway, lets see how the program performs
in extreme cases ;-)
can we give some cryptic text? with all symbols ^^$%^@)(#)!&# ?
nonsense! of course we can!, until the chars are ASCII
there should be no problem at all !
DES is cool ;)
next AES - AKA Rijndael :-D
