/**
    @file io.h
    @author John Butterfield (jpbutte2)
    Header file for the input/output component. This component
    will be responsible for botht the reading and writing of 
    files that the DES algorithm encrypted or decrypted.
*/

#include <stdio.h>
#include "DES.h"

/**
    This function reads up to 8 bytes from the given input file, 
    storing them in the data array of block and setting the len 
    field to indicate how many bytes have been read.
    @param fp a pointer to a file to read from
    @param block a pointer to a DESBlock structure representing a block
                of memory that will be filled by this function
*/
void readBlock( FILE *fp, DESBlock *block );

/**
    This function writes the contents of the data array in block 
    to the given file. The len field of block indicates how many 
    bytes the block contains.
    @param fp a pointer to a file to write to
    @param block a pointer to a DESBlock structure representing a
                block of memory to write to a given file
*/
void writeBlock( FILE *fp, DESBlock const *block );
