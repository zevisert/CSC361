#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "TraceParse.h"


#define VERBOSE 1

/* I want booleans! */
typedef enum { true, false } bool;

int main(int count, char** args)
{
    /*Check input args*/
    count = verify_input(args);
    if (count == 0) quit("No valid input files");
    
    pcap_t* cap;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i;
    for (i = 1; i <= count; ++i)
    {
        if ((cap = pcap_open_offline(args[i], errbuf)) == NULL)
        {
            printf("Couldn't open file %s\nReason: %s\n", args[i], errbuf);
            continue;
        }
        else if (VERBOSE) printf("Opened cap file %s\n", args[i]);
        dump_tcp(cap);
        pcap_close(cap);
    }

    quit("Source code not complete");
    return EXIT_SUCCESS;
}

void quit(char* message)
{
    if (message != NULL)
    {
        printf("\n%s\n", message);
    }
    else printf("\n");

    printf("Exiting...\n");
    exit(EXIT_FAILURE);
}

/*
    Validates a list of input arguments
    Modifies the input string array to contain only valid files on return
    Input:
        An array of pointers to strings to test
    Return:
        Number of valid cap files in input
    Output:
        Input arg is modified by ref to contain only valid cap files
*/
int verify_input(char** args)
{
    /* Skip program name */
    args++;
    
    int numFiles = 0;
    int i = 0;
    char** argPtr = args;
    char* ext = NULL;
    
    bool shift = false;

    /* Count strings and reset argPtr to start*/
    for ( ; *argPtr; ++numFiles, ++argPtr);
    argPtr = args;
    
    /* While there's more input strings */ 
    while (*argPtr && strlen(*argPtr))
    {
        /* From right to left, find the first '.' in the string */
        if( (ext = strrchr(*argPtr, '.')) != NULL)
        {
            /* If everything after the point above is .cap */
            if(strcmp(ext, ".cap") == 0)
            {
                /* Good, input file ends in .cap */
                FILE* file = fopen(*argPtr, "r");
                if (file == NULL)
                {
                    printf("ERR: File %s doesn't exist, or doesn't have read permissions\n", *argPtr);
                    shift = true;
                }
                /* Just checking if the file exists, we're done now */
                else fclose(file);
            }
            /* The remainder of the string wasn't .cap */
            else
            {
               if (VERBOSE) printf("ERR: File %s is not a .cap file.\n", *argPtr);
               shift = true;
            }
        }
        /* The whole string didn't have a '.' in it */
        else
        {
            if (VERBOSE) printf("ERR: File %s has no extension.\n", *argPtr);
            shift = true;
        }
        
        /* The input we tested wasn't a .cap file */ 
        if (shift == true)
        {
            shift = false;
            char** currString = argPtr;
            int j = i;
            /* From the current point on, copy strings down an index */ 
            for (++currString; *currString; ++currString, ++j)
            {
                args[j] = *currString;
            }
            /* Nullify the last string */
            args[j] = "\0";

            /* Decrease the number of valid input files */ 
            numFiles -= 1;
        }
        /* Didn't shift the input array down, look at the next string */
        else
        {
            if (VERBOSE) printf("File %s exists\n", *argPtr);
            ++argPtr;
            ++i;
        }
    }
    return numFiles;
}

void dump_tcp(pcap_t* cap)
{
    

}
