#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ndn/ndn.h>
#include <ndn/uri.h>
#include <ndn/keystore.h>
#include <ndn/signing.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "node_id.h"
#include "conf.h"

//#define DEBUG
#define TRACE_PREFIX "/trace"

void usage(void);

//This is the node node_id. IP address for now.
//This can be replaced by any unique ID.
char node_id[128] = {0};

//packet format
struct data
{
    uint32_t num_message;
    uint32_t *message_length;
    char **fwd_message;
};


enum ndn_upcall_res incoming_interest(struct ndn_closure *selfp,
                                      enum ndn_upcall_kind kind, struct ndn_upcall_info *info)
{
    //this is the callback function, all interest matching ndnx:/trace
    //will come here, handle them as appropriate
    int res = 0;
    const unsigned char *ptr;
    size_t length;
    int i;

    //data structure for the reply packet
    struct data reply;

    char *delims = "~";
    int hop = 0;
    char *result = NULL;
    //switch on type of event
    switch (kind)
    {
    case NDN_UPCALL_FINAL:
        free(selfp);
        return NDN_UPCALL_RESULT_OK;

    case NDN_UPCALL_CONTENT:

        //get the content from packet
        res = ndn_content_get_value(info->content_ndnb, info->pco->offset[NDN_PCO_E], info->pco, &ptr, &length);
        if (res < 0)
        {
            printf("Can not get value from content. res: %d", res);
            exit(1);
        }

        //copy number of messages from packet
        memcpy(&reply.num_message, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
#ifdef DEBUG
        printf("Number of messages %d\n", reply.num_message);
#endif

        //store length of each message in an int array
        reply.message_length = malloc(sizeof(uint32_t)*reply.num_message);
        for(i=0; i < reply.num_message; i++)
        {
            memcpy(&reply.message_length[i], ptr, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
        }

        //allocate memory of num_message number of messages
        //in the loop, we allocate memory for each of those messages
        reply.fwd_message = malloc(sizeof(char *) * reply.num_message);
        for(i=0; i < reply.num_message; i++)
        {
            reply.fwd_message[i] = malloc(sizeof(char) * reply.message_length[i]);
            memcpy(reply.fwd_message[i], ptr, reply.message_length[i]);
            ptr += reply.message_length[i];
#ifdef DEBUG
            printf("%s\n", reply.fwd_message[i]);
#endif
            //break the forward messages and print them

            hop = 0;
            result = NULL;
            printf("\n**********Route %d************\n", i);
            result = strtok(reply.fwd_message[i], delims);
            while( result != NULL ) {
                printf( "%d: %s \n", hop, result );
                result = strtok( NULL, delims );
                hop++;
            }

            free(reply.fwd_message[i]);
        }

        printf("\n***************************\n");
        //free the memory we allocated
        free(reply.message_length);
        free(reply.fwd_message);

        //we are done, exit
        exit(0);
        break;

        //default timeout in ndn is 4 secs, number of retries are decided by timeout argument
        //devided by 4 secs.
    case NDN_UPCALL_INTEREST_TIMED_OUT:
        printf("asked again...waiting for reply\n");
        return NDN_UPCALL_RESULT_REEXPRESS;

    case NDN_UPCALL_CONTENT_UNVERIFIED:
        fprintf(stderr, "%s: Error - Could not verify content\n\n", CLI_PROGRAM);
        return NDN_UPCALL_RESULT_ERR;

    case NDN_UPCALL_CONTENT_BAD:
        fprintf(stderr, "%s: Error - Bad content\n\n", CLI_PROGRAM);
        return NDN_UPCALL_RESULT_ERR;

    case NDN_UPCALL_INTEREST:
        //don't care about interests, will do nothing
        break;

    default:
        printf("Unexpected response\n");
        return NDN_UPCALL_RESULT_ERR;

    }

    return(0);
}

void usage(void)
{
    ///prints the usage and exits
    printf("%s version %s \n", CLI_PROGRAM, CLI_VERSION);
    printf("%s -u URI [-t] TIMEOUT(ms) [-h] [-V] \n\n", CLI_PROGRAM);

    printf("  -u URI         URI to trace to\n");
    printf("  -t TIMEOUT     set timeout in milisecond, default 30 sec\n");
    printf("  -h             print this help and exit\n");
    printf("  -V             print version and exit\n\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    int opt;
    char *URI = NULL;
    char *timeout = NULL;
    int timeout_ms = 60000;
    int res = 0;

    //check if user supplied uri to trace to, read the arguments and check them
    if(argc < 3)
    {
        fprintf(stderr, "%s: Error - Not enough arguments\n\n", CLI_PROGRAM);
        usage();
    }

    while((opt = getopt(argc, argv, "hV:u:t:")) != -1)
    {
        switch(opt)
        {
        case 'h':
            usage();
            break;
        case 'V':
            printf("%s %s\n\n", CLI_PROGRAM, CLI_VERSION);
            exit(0);
        case 'u':
            URI = optarg;
            break;
        case 't':
            timeout = optarg;
            res = sscanf(timeout, "%d", &timeout_ms);
            if(res == 0)
            {
                fprintf(stderr, "%s: Error - Could not convert timeout value to int %s\n\n", CLI_PROGRAM, timeout);
                usage();
            }
            break;
        case ':':
            fprintf(stderr, "%s: Error - Option `%c' needs a value\n\n", CLI_PROGRAM, optopt);
            usage();
            break;
        case '?':
            fprintf(stderr, "%s: Error - No such option: `%c'\n\n", CLI_PROGRAM, optopt);
            usage();
            break;
        }
    }

    //get the node_id, IP address for now
    if (get_ip_addresses(node_id) == NULL)
    {
        fprintf(stderr, "Can not get node_id\n");
        exit(1);
    }

    //print node id
#ifdef DEBUG
    printf("Node ID:%s\n", node_id);
# endif

    //get the length of user provided URI
    size_t argv_length = strlen(URI);

    //check first six chars for ndnx:/, if present, skip them
    int skip = 0;
    res = strncmp("ndnx:/", URI, 6);
    if(res == 0)
    {
        skip = 5;
    }


    if(strncmp("ndnx:/trace", URI, 11) == 0 || strncmp("/trace", URI, 6)== 0)
    {
        printf("Don't include /trace in the URI\n");
        usage();  
    }



    //if URI does not begins with /, exit
    if (URI[skip] != '/')
    {
        printf("URI must begin with /\n");
        exit(1);
    }

    //check if uri ends with slash, append if missing
    char *slash = "";
    if (URI[argv_length-1] != '/')
    {
        slash = "/";
    }
    char *tilde = "~";

    //allocate memory for
    //trace URI = /trace/user_input/random_number/~/forward_path(ID of self)

    char *TRACE_URI = (char *) calloc(strlen(TRACE_PREFIX)+ strlen(URI+skip) + 1 + 100 + 1 + 1 +128 + 1, sizeof(char)) ; //find size of rand
    if(TRACE_URI == NULL)
    {
        fprintf(stderr, "Can not allocate memory for URI\n");
        exit(1);
    }

    //put together the trace URI, add a random number to end of URI, this is the one we
    //are actually going to use in the interest packet
    srand ((unsigned int)time (NULL)*getpid());
    sprintf(TRACE_URI, "%s%s%s%d%s%s%s", TRACE_PREFIX, URI+skip, slash, rand(), tilde, slash, node_id);

#ifdef DEBUG
    printf("%s\n", TRACE_URI);
#endif


    //allocate memory for interest
    struct ndn_charbuf *ndnb = ndn_charbuf_create();
    if(ndnb == NULL)
    {
        fprintf(stderr, "Can not allocate memory for interest\n");
        exit(1);
    }


    //adding name to interest
    res = ndn_name_from_uri(ndnb, TRACE_URI);
    if(res == -1)
    {
        fprintf(stderr, "Failed to assign name to interest");
        exit(1);
    }

    //create the ndn handle
    struct ndn *ndn = ndn_create();
    if(ndn == NULL)
    {
        fprintf(stderr, "Can not create ndn handle\n");
        exit(1);
    }

    //connect to ndnd
    res = ndn_connect(ndn, NULL);
    if (res == -1)
    {
        fprintf(stderr, "Could not connect to ndnd... exiting\n");
        exit(1);
    }

#ifdef DEBUG
    printf("Connected to NDND, return code: %d\n", res);
#endif

    printf("trace to %s\n", URI);

#ifdef DEBUG
    printf("Full interest name %s\n", TRACE_URI);
#endif
    struct ndn_closure *incoming;
    incoming = calloc(1, sizeof(*incoming));
    incoming->p = incoming_interest;
    res = ndn_express_interest(ndn, ndnb, incoming, NULL);
    if (res == -1)
    {
        fprintf(stderr, "Could not express interest for %s\n", URI);
        exit(1);
    }


    //run for timeout miliseconds
    res = ndn_run(ndn, timeout_ms);
    if (res < 0)
    {
        fprintf(stderr, "ndn_run error\n");
        exit(1);
    }

    //there is a memory leak for incoming, figure a way to free ndn_closure
    free(TRACE_URI);
    ndn_charbuf_destroy(&ndnb);
    ndn_destroy(&ndn);
    exit(0);

}
