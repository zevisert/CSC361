/*------------------------------
* TCP_util.c
* Description: Some util functions
* CSC 361 - Assignment 1
* Author: Zev Isert
-------------------------------*/

#define ZeroMemory(X) memset(&X, 0, sizeof X)

/* Print a reason for exit, and end the program */
void quit(const char* reason)
{
	if (reason != NULL)
	{
		printf("\nFault: %s\n", reason);
	}
	printf("Exiting.\n");
	exit(EXIT_FAILURE);
}

/* write "size" bytes of "ptr" to "sd" */
int writen(int sd, char *ptr, int size)
{
    int no_left, no_written;

    no_left = size; 
    while (no_left > 0)
    {
       no_written = write(sd, ptr, no_left);
       if (no_written <=0)
            return(no_written);
       no_left -= no_written;
       ptr += no_written;
    }
    return(size - no_left);
}
