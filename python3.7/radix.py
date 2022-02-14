#  (C) Copyright 2017, 2018 Crash Avoidance Metrics Partners LLC, VSC5 Consortium
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
# 
radix_256 = 2**256
radix_128 = 2**128
radix_32 = 2**32
radix_16 = 2**16
radix_8  = 2**8

def Hex(n, radix=0):
    '''Converts n to a hex string.
       If radix is not 0, pads to the max number of characters for digits modulo the radix.
       Uses capital letters, and no trailing L.
    '''
    if n < 0:
        signum = "-"
    else:
        signum = ""

    nh = hex(abs(n))[2:]

    if nh.find("L") >= 0:
        nh = nh[:-1]

    pad = (len(bin(radix)))/4  # -3 for the 0b[01], but then +3 for the round up.

    if pad >= len(nh):
        pad -= len(nh)
    else:
        pad = 0

    return(signum + "0x" + int(pad)*"0" + nh.upper())


def int2lelist(n, radix, listlen=0):
    '''Converts n to a little-endian list of length at least listlen in the given radix.
    '''
    if n < 0:
        n = -n
    elif n == 0:
       nlist = [0]
    else:
       nlist = []

    while n:
        nlist.append(int(n % radix))
        n = n // radix

    while len(nlist) < listlen:
        nlist.append(0)

    return nlist[:]


def belist2int(nlist, radix):
    '''Converts n from a big-endian list in the given radix to an integer.
    '''
    n = 0
    for ndigit in nlist:
        n *= radix
        n += ndigit

    return n


def int2belist(n, radix, listlen=0):
    '''Converts n to a big-endian list of length at least listlen in the given radix.
    '''
    nlist = int2lelist(n, radix, listlen)
    nlist.reverse()

    return nlist[:]


def lelist2int(nlist, radix):
    '''Converts n from a little-endian list in the given radix to an integer.
    '''
    nlist_rev = nlist[:]
    nlist_rev.reverse()

    return belist2int(nlist_rev, radix)

def long2hexstr(n, bitlen):
    '''Converts n to a hex string, where n is of bitlength bitlen
    '''
    return "{0:0>{width}X}".format(n, width=((bitlen*2)+7)/8)
