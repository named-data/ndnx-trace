#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ndn/ndn.h>
#include <ndn/uri.h>
#include <ndn/keystore.h>
#include <ndn/signing.h>
#include <ndn/charbuf.h>
#include <ndn/reg_mgmt.h>
#include <ndn/ndn_private.h>
#include <ndn/ndnd.h>
#include <ndn/hashtb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <pthread.h>

#include "node_id.h"
#include "conf.h"

#define DEBUG

char node_id[128] = {0};
char *slash = "/";
char *tilde = "~";

//for discarding duplicate interests
int prev_interest = 0;
int num_reply = 0;
int recv_reply = 0;

int processed_random[100000];
int processed_index = 0;

//for logging
FILE *logfile;
int log_exist = 0;

//data packet
struct data {
    uint32_t num_message;
    uint32_t *message_length;
    char **fwd_message;
};

//pass data to threads
struct pass_thread_args {
    int  p_thread_id;
    char *p_interest_random_str;
    char *p_interest_name;
    char *p_forward_path;
    char *p_remote_ip;
};

pthread_t *forwarding_threads;


//get data from threads
struct thread_reply {
    int status_code;
    int num_reply;
    char **reply;
};

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;



int find_interest_name(const unsigned char *interest_msg,
                       struct ndn_parsed_interest *pi, char **interest_name,
                       char **interest_rand_str, char **forward_path) {
    //-----------------------------------------------------------------------//
    /// Arguments are interest message and parsed interest. Sets interest name
    /// and the interest random component for future usage
    //-----------------------------------------------------------------------//

    //get the full interest name
    int res;

    struct ndn_charbuf *name = ndn_charbuf_create();
    res = ndn_charbuf_append(name, interest_msg + pi->offset[NDN_PI_B_Name],
                             pi->offset[NDN_PI_E_Name] - pi->offset[NDN_PI_B_Name]);
    if (res < 0) {
        fprintf(logfile, "find_interest_name: Could not get interest name. Res = %d\n", res);
        fclose(logfile);
        return(1);
    }

    struct ndn_charbuf *uri = ndn_charbuf_create();
    ndn_uri_append(uri, name->buf, name->length, 1);
    fprintf(logfile, "\nIncoming Interest = %s\n", ndn_charbuf_as_string(uri));
    fflush(logfile);

    //copy the name over to a string, set the reset pointer to string
    char *uri_string = malloc(strlen(ndn_charbuf_as_string(uri))+1);
    char *reset_uri_string;
    strcpy(uri_string, ndn_charbuf_as_string(uri));

    //remove the ndnx:/trace from the beginning of interest name
    reset_uri_string = uri_string;
    uri_string = uri_string + strlen("ndnx:/trace");

    //break the uri in two parts, uri and forward path
    char *fwd_path, *base_uri;
    base_uri = strtok(uri_string, "~");
    fwd_path = strtok(NULL, "~");
    if (base_uri == NULL || fwd_path == NULL) {
        fprintf(logfile, "Can not split URI\n");
        fclose(logfile);
        return(1);
    }

    //get the random component, copy to int, get the id, copy to path
    char *l_random_component = strrchr(uri_string, '/') + 1;
    fprintf(logfile, "Base uri %s Random component %s Forwarded path %s Length %zu \n", base_uri, l_random_component, fwd_path,  strlen(l_random_component));
    fflush(logfile);

    //set the last_comp and fwd_path to the passed vars,
    //add a / at the end of fwd path
    *forward_path = calloc(strlen(fwd_path)+1+1, sizeof(char));
    sprintf((char *)*forward_path, "%s%s", fwd_path, slash);

    //get the remaining name, set it to interest name
    //uri - -len of ndnx:/trace - len of last component - 1 for the / + 1 for the \n
    int truncated_uri_length =  strlen(uri_string) - strlen(l_random_component) - 1 ;
    fprintf(logfile, "uri length%d\n", truncated_uri_length);
    fflush(logfile);
    *interest_name = calloc(truncated_uri_length + 1, sizeof(char)) ;
    if (interest_name == NULL) {
        fprintf(logfile, "Can not allocate memory for interest_name\n");
        exit(1);
    }
    strncpy((char *)*interest_name, uri_string, truncated_uri_length);

    //copy the random component
    *interest_rand_str = calloc(strlen(l_random_component) + 1, sizeof(char));
    strncpy(*interest_rand_str, l_random_component, strlen(l_random_component));

    //free data structures
    //reset before freeing string
    uri_string = reset_uri_string;
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&uri);
    free(uri_string);
    return(0);
}


int check_duplicate_interests(char *l_interest_name, char *l_interest_rand_str, char *l_fwd_path) {
#ifdef DEBUG
    printf("check dup %s %s %s\n", l_interest_name, l_interest_rand_str, l_fwd_path);
#endif

    //we want to check if the interest is from local client
    //in this case, the forward path will be /192.168.1.1/
    //if it is looping interest, this won't match

    char node_id_with_slash[130] = {0};
    sprintf(node_id_with_slash, "/%s/", node_id);

    //if fwd path exact same as node_id, interest is from local client, not
    //looping && interest is not from local client and the id is in fwd_path
    //then the interest is looping
    int interest_random_int = 0;
    int iter =0;
    sscanf((const char * )l_interest_rand_str, "%d", &interest_random_int);

    //check for duplicate messages, return 1
    for (iter = 0; iter < processed_index; iter++) {
        if (processed_random[iter] == interest_random_int) {
            fprintf(logfile, "duplicate interest, random value = %d\n",processed_random[iter]);
            fflush(logfile);
            return(1);
        }
    }

    if (strcmp(node_id_with_slash, (const char *)l_fwd_path) !=0 && strstr((const char *)l_fwd_path, node_id_with_slash) !=NULL) {
        fprintf(logfile, "Interest %s%s%s%s came from remote client and duplicate\n", l_interest_name, slash, l_interest_rand_str, l_fwd_path);
        fflush(logfile);
        return(1);
    }


    //record the random number
    processed_random[processed_index] = interest_random_int;
    processed_index ++;
    return(0);
}


int get_faces(char *interest_name, char **faces, int *num_faces, const unsigned char **longest_match, char **matching_fib_entry) {

    //-----------------------------------------------------------------------//
    ///Takes the interest name, fills in matching faces, number of faces
    ///and the longest match
    //-----------------------------------------------------------------------//

    fprintf(logfile, "finding faces for %s\n", interest_name);
    fflush(logfile);

    char command_find_faces[1024] = {0};
    char command_fib_entry[1024] = {0};
    char readbuf[1024]= {0};
    int face_index=0;
    int default_rt_flag = 0;

    //make a duplicate of interest name
    char *search_str;

    //allocate two extra bytes, one for newline, one for ndnx:/ for default
    if ((search_str = malloc (strlen((const char *)interest_name) + strlen("ndnx:") + 2)) != NULL) {
        //strcpy (search_str, (const char*)interest_name);
        sprintf (search_str, "%s%s", "ndnx:", (const char*)interest_name);
    }
    int len_search_str = strlen((const char *)search_str);

    //parse the ndndstatus for match
    while (len_search_str > 0) {
        sprintf(command_find_faces, "%s%s%s%s", NDN_DIR, "ndndstatus|grep '", search_str, " '|awk -F 'face:' '{print $2}' |awk '{print $1}'|sort|uniq");
        fprintf(logfile, "%s\n", command_find_faces);
        fflush(logfile);

        //execute the command
        FILE *fp = popen(command_find_faces, "r");
        if (fp == NULL) {
            fprintf(logfile, "can not execute ndndstatus\n");
            fclose(logfile);
            pclose(fp);
            exit(1);
        }

        //read buffer and get the first match
        while (fgets(readbuf, 1024, fp) != NULL) {
            readbuf[strlen(readbuf)-1] = '\0';
            faces[face_index] = malloc(strlen(readbuf)+1);
            memset(faces[face_index],0,strlen(readbuf)+1);
            strncpy(faces[face_index], readbuf, strlen(readbuf));
            face_index++;
        }
        pclose(fp);

        //if faces are found, we are done, no need to match shorter prefixes, search_str is the prefix
        // find the fib entry and set it
        if (face_index > 0) {
            *longest_match = malloc(sizeof(char) * strlen(search_str) + 1);
            if (longest_match== NULL) {
                fprintf(logfile, "Can not allocate memory for longest_match\n");
                fclose(logfile);
                exit(1);
            }
            strcpy((char *)*longest_match, search_str);

            //find the fib entry that matched, mind the space at the end of search str, don't do -w
            sprintf(command_fib_entry, "%s%s%s%s", NDN_DIR, "ndndstatus|grep '", search_str, " '|awk '{print $1}'|head -n 1");
            fprintf(logfile, "%s\n", command_fib_entry);
            fflush(logfile);

            //execute the command
            fp = popen(command_fib_entry, "r");
            if (fp == NULL) {
                fprintf(logfile, "can not execute ndndstatus\n");
                fclose(logfile);
                pclose(fp);
                exit(1);
            }

            //read buffer and get the first match
            memset(readbuf, 0, 1024);
            while (fgets(readbuf, 1024, fp) != NULL) {
                *matching_fib_entry = calloc(strlen(readbuf)+1, sizeof(char));
                //don't copy the newline
                strncpy(*matching_fib_entry, readbuf, strlen(readbuf)-1);
            }
            fprintf(logfile,"longest match %s strlen %zu, fib entry %s length %zu\n", *longest_match,  strlen((const char *)*longest_match), *matching_fib_entry, strlen((const char *)*matching_fib_entry));
            fflush(logfile);

            pclose(fp);
            free(search_str);
            break;
        }

        //else, remove last component and retry
        fprintf(logfile, "string before removal of last comp: %s\n", search_str);
        fflush(logfile);

        char *last_component = strrchr(search_str, '/');
        if (last_component != NULL) {
            fprintf(logfile, "last component %s len %zu\n", last_component, strlen(last_component));
            fflush(logfile);
            *last_component = '\0';
        }

        fprintf(logfile, "string after removal: %s length: %zu default route flag %d\n", search_str, strlen(search_str), default_rt_flag);
        fflush(logfile);

        //search for default route
        if (strcmp(search_str, "ndnx:") == 0 && default_rt_flag == 0) {
            sprintf(search_str, "%s", "ndnx:/");
            default_rt_flag = 1;
        } else if (strcmp(search_str, "ndnx:") == 0)
            break;
        len_search_str = strlen(search_str);
    }

    fprintf(logfile, "number of faces %d\n", face_index);
    fflush(logfile);

    //set the num_faces
    *num_faces = face_index;

    return(0);
}


int find_remote_ip(char **face, int number_faces, char **return_ips, int *num_remote_ips) {

    //-----------------------------------------------------------------------//
    ///Takes the list of faces for a prefix, finds the IP addresses from FIB
    //-----------------------------------------------------------------------//

    int iter1 = 0;
    int return_ip_index = 0;
    char command2[1024] = {0};
    char fib_entry[1024] = {0};

    //for each face, find the matching ip address
    for (iter1 = 0; iter1 < number_faces; iter1++) {
        sprintf(command2, "%s%s%s%s", NDN_DIR, "ndndstatus |grep -w 'pending'|grep -w 'face: ", face[iter1], "'|awk -F 'remote:' '{print $2}' |awk -F ':' '{print $1}'|tr -s '\\n'|head -n 1");
        fprintf(logfile, "Command_face %s\n", command2);

        //execute command
        FILE *fp2 = popen(command2, "r");
        if (fp2 == NULL) {
            fprintf(logfile, "can not execute ndndstatus\n");
            fclose(logfile);
            pclose(fp2);
            exit(1);
        }

        //store the matching IPs
        while (fgets(fib_entry, 80, fp2) != NULL) {
            fib_entry[strlen(fib_entry)-1] = '\0';

            //////////////////////cleanup at calling function/////////////////
            return_ips[return_ip_index] = malloc(strlen(fib_entry)+1);
            if (return_ips[return_ip_index]== NULL) {
                fprintf(logfile, "Can not allocate memory for storing remote IP\n");
                fclose(logfile);
                pclose(fp2);
                exit(1);
            }
            memset(return_ips[return_ip_index],0,(strlen(fib_entry)+1));
            strncpy(return_ips[return_ip_index], fib_entry, strlen(fib_entry));
            return_ip_index++;
            fprintf(logfile, "storing ip address %s\n", fib_entry);
        }
        pclose(fp2);
    }

    //set the number of ips found
    //check readbuf length if we indeed found a route, not a blank line
    if (strlen(fib_entry) > 0)
        *num_remote_ips = return_ip_index;
    return(0);
}

char* swap_random(char *interest_name, char *interest_random_comp, const char *fwd_path, char **new_interest_name, char **new_interest_random_comp) {
    //-----------------------------------------------------------------------//
    ///Takes an interest name, swaps the random component for forwarding,
    //appends path id. The random seed is declared in the main.
    //-----------------------------------------------------------------------//

    fprintf(logfile, "Swap random, interest name %s  random %s fwd_path %s\n", interest_name, interest_random_comp, fwd_path);
    printf("Swap random, interest name %s  random %s fwd_path %s\n", interest_name, interest_random_comp, fwd_path);

    int rand_comp = rand();
    *new_interest_random_comp = calloc(128, sizeof(char));
    sprintf(*new_interest_random_comp, "%d", rand_comp);

    char *trace = "/trace";
    char *new_fwd_path = calloc(strlen(fwd_path) + strlen(node_id) + strlen(slash) + 1, sizeof(char));
    sprintf(new_fwd_path, "%s%s", fwd_path, node_id);

    ////////////////////free at callling function/////////////
    *new_interest_name = calloc(strlen(trace) +strlen((const char *)interest_name) + strlen(slash) + strlen(*new_interest_random_comp) + strlen(tilde) + strlen(new_fwd_path) + 1, sizeof(char));
    if (new_interest_name == NULL) {
        fprintf(logfile, "Can not allocate memory for new_interest_name\n");
        fclose(logfile);
        exit(1);
    }
    sprintf(*new_interest_name, "%s%s%s%s%s%s", trace, interest_name, slash, *new_interest_random_comp, tilde, new_fwd_path);
    fprintf(logfile, "Forwarding interest %s with random component %d\n\n\n", *new_interest_name, rand_comp);
    fflush(logfile);

    //housekeeping
    //free(new_rand_comp);
    return(0);
}

const unsigned char* manage_route(char *forwarding_interest_name, char *fwd_ip, int action) {

    //-----------------------------------------------------------------------//
    /// Takes an interest name and remote IP. Adds or deletes a route based
    /// on action. Action 0 = add, 1 = delete
    //-----------------------------------------------------------------------//

    FILE *fp;

    //if we are adding route
    if (action == 0) {
        int add_route_length = strlen(NDN_DIR) +strlen("ndndc add ") + strlen(forwarding_interest_name) + strlen(" udp") +  strlen(fwd_ip) +1;
        char *add_route = malloc(add_route_length);
        if (add_route == NULL) {
            fprintf(logfile, "Can not allocate memory for add route command\n");
            fclose(logfile);
            exit(1);
        }
        sprintf(add_route, "%s%s%s%s%s", NDN_DIR, "ndndc add ", forwarding_interest_name, " udp", fwd_ip);
        fprintf(logfile, "adding route %s\n", add_route);
        fflush(logfile);

        //execute the command
        fp = popen(add_route, "r");
        if (fp == NULL) {
            fprintf(logfile, "can not add route\n");
            fclose(logfile);
            pclose(fp);
            exit(1);
        }
        pclose(fp);
        free(add_route);
    }

    //delete a route
    else if (action == 1) {
        int del_route_length = strlen(NDN_DIR) + strlen("ndndc del ") + strlen(forwarding_interest_name) + strlen(" udp") +  strlen(fwd_ip) +1;
        char *del_route = malloc(del_route_length);
        if (del_route == NULL) {
            fprintf(logfile, "Can not allocate memory for del route command\n");
            fclose(logfile);
            exit(1);
        }

        sprintf(del_route, "%s%s%s%s%s", NDN_DIR, "ndndc del ", forwarding_interest_name, " udp", fwd_ip);
        fprintf(logfile,"deleting route %s\n", del_route);
        fflush(logfile);

        //execute the command
        fp = popen(del_route, "r");
        if (fp == NULL) {
            fprintf(logfile, "can not add route\n");
            fclose(logfile);
            pclose(fp);
            exit(1);
        }
        pclose(fp);
        free(del_route);
    }
    return(0);
}

int construct_trace_response(struct ndn *h, struct ndn_charbuf *data,
                             const unsigned char *interest_msg, const struct ndn_parsed_interest *pi, unsigned char *mymsg, size_t size) {

    //-----------------------------------------------------------------------//
    /// Constructs the trace response, signs them. data is sent by upcall
    //-----------------------------------------------------------------------//

    struct ndn_charbuf *name = ndn_charbuf_create();
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    int res;
    res = ndn_charbuf_append(name, interest_msg + pi->offset[NDN_PI_B_Name],
                             pi->offset[NDN_PI_E_Name] - pi->offset[NDN_PI_B_Name]);
    if (res == -1) {
        fprintf(logfile, "Can not copy interest name to buffer\n");
        fclose(logfile);
        exit(1);
    }

    //sign the content, check if keystore exsists
    res = ndn_sign_content(h, data, name, &sp,  mymsg, size);
    if (res == -1) {
        fprintf(logfile, "Can not sign content\n");
        fclose(logfile);
        exit(1);
    }

    //free memory and return
    ndn_charbuf_destroy(&sp.template_ndnb);
    ndn_charbuf_destroy(&name);
    return res;
}


//void *get_fwd_reply(char *new_interest_name, char **fwd_reply, int *num_reply, char *remote_ip)
static void *get_fwd_reply(void *arguments) {
    //-----------------------------------------------------------------------//
    /// forwards the interests and wait for reply. Timeout is hardcoded 8 secs.
    /// input is interest name to forward, sets the reply array (of strings)
    /// if a get times out, appends the remote ip with message and sets the
    /// appropriate string.
    //-----------------------------------------------------------------------//
    int res;
    struct pass_thread_args *args = arguments;

#ifdef DEBUG
    printf("Inter name %s\n", args ->p_interest_name);
    printf("thread id %d\n", args -> p_thread_id);
    printf("random %s\n", args -> p_interest_random_str);
    printf("forward path %s\n", args -> p_forward_path);
    printf("remote_ip %s\n", args -> p_remote_ip);
#endif
    //pthread_exit(NULL);

    char *interest_name = args->p_interest_name;
    char *fwd_path = args->p_forward_path;
    char *remote_ip = args->p_remote_ip;

    char new_interest_name[1024] = {0};
    char new_interest_random_comp[128] = {0};
    int rand_comp = rand();

    //new component
    sprintf(new_interest_random_comp, "%d", rand_comp);
    //new interest name
    sprintf(new_interest_name, "/trace%s/%s~%s%s", interest_name, new_interest_random_comp, fwd_path, node_id);

    //log
    fprintf(logfile, "Forwarding interest %s with random component %d\n\n\n", new_interest_name, rand_comp);
    fflush(logfile);
#ifdef DEBUG
    printf("New interest %s new_interest rand%s\n", new_interest_name, new_interest_random_comp);
#endif

    //send back reply
    struct thread_reply * p_thread_reply = calloc (1, sizeof (struct thread_reply));
    //do a duplicate check to enroll the new interests
    pthread_mutex_lock(&mutex);
    res = check_duplicate_interests(new_interest_name, new_interest_random_comp, args->p_forward_path);
    if (res  == 1) {
        p_thread_reply->status_code = 1;
        pthread_mutex_unlock(&mutex);
        pthread_exit((void *)p_thread_reply);

    }

    //add route
    manage_route(new_interest_name, remote_ip, 0);

    int i =0;
    //char fwd_reply[100][100];
    char **fwd_reply;
    int num_reply;

    struct data mymsg;
    mymsg.num_message = 0;

    //create the ndn handle
    struct ndn *ndn_fwd = ndn_create();
    if (ndn_fwd == NULL) {
        fprintf(logfile, "Can not create ndn handle\n");
        fclose(logfile);
        exit(1);
    }

    struct ndn_charbuf *ndnb_fwd = ndn_charbuf_create();
    if (ndnb_fwd == NULL) {
        fprintf(logfile, "Can not allocate memory for interest\n");
        fclose(logfile);
        exit(1);
    }
    res = ndn_name_from_uri(ndnb_fwd, (const char *)new_interest_name);
    if (res == -1) {
        fprintf(logfile, "Failed to assign name to interest");
        fclose(logfile);
        exit(1);
    }

    //connect to ndnd
    res = ndn_connect(ndn_fwd, NULL);
    if (res == -1) {
        fprintf(logfile, "Could not connect to ndnd... exiting\n");
        fclose(logfile);
        exit(1);
    }
    fprintf(logfile, "Connected to NDND, return code: %d\n", res);
    fflush(logfile);

    //allocate buffer for response
    struct ndn_charbuf *resultbuf = ndn_charbuf_create();
    if (resultbuf == NULL) {
        fprintf(logfile, "Can not allocate memory for URI\n");
        fclose(logfile);
        exit(1);
    }

    //setting the parameters for ndn_get
    struct ndn_parsed_ContentObject pcobuf = { 0 };
    pthread_mutex_unlock(&mutex);

    //randomize the ndn_get so that the nodes don't sync
    //if request is from local client, increase the timeout by 4

    int pos = 0;
    int tilde_index = 0;
    int hop_count = 0;
    for (pos = 0; new_interest_name[pos]!='\0'; pos++) {
        if(new_interest_name[pos] == '~')
            tilde_index = pos;
    }

    for (pos = tilde_index; new_interest_name[pos]!='\0'; pos++) {
        if(new_interest_name[pos] == '/')
            hop_count++;
    }
    fprintf(logfile,"Hop count %d\n", hop_count);
    fflush(logfile);

    char double_node_id [256] = {0};
    sprintf(double_node_id, "%s%s%s%s", slash, node_id, slash, node_id);

    int timeout_ms = 10000 + rand()%20 - hop_count*1500;
    if (strstr(new_interest_name, double_node_id)!= NULL) {
        timeout_ms *= 2;
    }

    printf("Timeout %d\n", timeout_ms);


    //express interest
    res = ndn_get(ndn_fwd, ndnb_fwd, NULL, timeout_ms, resultbuf, &pcobuf, NULL, 0);
    if (res == -1) {
#ifdef DEBUG
        printf("Did not receive answer for trace to %s res = %d\n", new_interest_name, res);
#endif
        fprintf(logfile, "Did not receive answer for trace to %s\n", new_interest_name);
        fflush(logfile);

        //if we did not receive answer, set the answer
        fwd_reply = calloc(1, sizeof(char *));
        fwd_reply[0] = calloc(strlen(remote_ip) + strlen("TIMEOUT TO")+ 1, sizeof(char));
        if (fwd_reply[0] == NULL) {
            fprintf(logfile, "Could not allocate memory for timeout reply message\n");
            fclose(logfile);
            exit(1);
        }
        sprintf(fwd_reply[0], "TIMEOUT TO%s", remote_ip);
        num_reply = 1;
    }

    else {
        pthread_mutex_lock(&mutex);
        //we received answer, parse it
        const unsigned char *ptr;
        size_t length;
        ptr = resultbuf->buf;
        length = resultbuf->length;
        ndn_content_get_value(ptr, length, &pcobuf, &ptr, &length);

        //check if received some data
        if (length == 0) {
#ifdef DEBUG
            fprintf(logfile, "Received empty answer for trace to URI: %s\n", new_interest_name);
            fflush(logfile);
#endif
        }

        memcpy(&mymsg.num_message, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        mymsg.message_length = malloc(sizeof(uint32_t)*mymsg.num_message);
        if (mymsg.message_length == NULL) {
            fprintf(logfile, "Could not allocate memory for storing fwd reply message length\n");
            fclose(logfile);
            exit(1);
        }
        for (i=0; i < mymsg.num_message; i++) {
            memcpy(&mymsg.message_length[i], ptr, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
        }

        //copy the replies to data packet
        mymsg.fwd_message = malloc(sizeof(char *) * mymsg.num_message +1);
        if (mymsg.fwd_message == NULL) {
            fprintf(logfile, "Could not allocate memory for fwd reply message number\n");
            fclose(logfile);
            exit(1);
        }
        for (i=0; i < mymsg.num_message; i++) {
            mymsg.fwd_message[i] = malloc (sizeof(char) * mymsg.message_length[i] +1);
            if (mymsg.fwd_message[i] == NULL) {
                fprintf(logfile, "Could not allocate memory for fwd reply message data\n");
                fclose(logfile);
                exit(1);
            }
            strncpy(mymsg.fwd_message[i], (const char *)ptr, mymsg.message_length[i]);
            ptr += mymsg.message_length[i];
            fprintf(logfile, "%s\n", mymsg.fwd_message[i]);
            fflush(logfile);
        }

        //set the replies
        fwd_reply = calloc(mymsg.num_message + 1,sizeof (char *));
        for (i=0; i < mymsg.num_message; i++) {
            fwd_reply[i] = calloc(mymsg.message_length[i] + 1,sizeof (char));
            if (fwd_reply[i] == NULL) {
                fprintf(logfile, "Could not allocate memory for reply\n");
                fclose(logfile);
                exit(1);
            }
            sprintf(fwd_reply[i], "%s", mymsg.fwd_message[i]);
        }
        num_reply = mymsg.num_message;

    }

    //pack the reply for main
    //delete route

    manage_route(new_interest_name, remote_ip, 1);
    pthread_mutex_unlock(&mutex);

    p_thread_reply->status_code = 0;
    p_thread_reply->num_reply = num_reply;
    p_thread_reply->reply = malloc(num_reply * sizeof(char *));
    for (i = 0; i<num_reply; i++) {
        p_thread_reply->reply[i] = calloc(strlen(fwd_reply[i])+1 ,sizeof(char));
        strncpy(p_thread_reply->reply[i], fwd_reply[i], strlen(fwd_reply[i]));
    }
    pthread_exit((void *)p_thread_reply);

    //we are done here
//    ndn_destroy(&ndn_fwd);
//    ndn_charbuf_destroy(&resultbuf);
//    ndn_charbuf_destroy(&ndnb_fwd);

}

enum ndn_upcall_res incoming_interest(struct ndn_closure *selfp,
                                      enum ndn_upcall_kind kind, struct ndn_upcall_info *info) {
    //-----------------------------------------------------------------------//
    /// callback function, all interest matching ndnx:/trace will come here,
    /// handle them as appropriate
    //-----------------------------------------------------------------------//

    switch (kind) {

    case NDN_UPCALL_FINAL:
        return NDN_UPCALL_RESULT_OK;
        break;

    case NDN_UPCALL_CONTENT:
        break;

    case NDN_UPCALL_INTEREST:

    {
        //status number
        int res = 0;

        // variables for interest name
        char *interest_name = NULL;
        //int interest_random_comp_int = 0;
        char *interest_rand_str = NULL;
        char *forward_path = NULL;

        //variables for finding faces
        char *faces[100]; //char* of faces
        int number_faces = 0;
        const unsigned char *longest_prefix = NULL;
        int i=0;
        struct data return_data;

        //variables for finding remote ips
        char *remote_ips[100];
        int num_remote_ips = 0;
        char *matching_fib_entry = NULL;
        int remote_ip_index = 0;


        //variables for fwd_reply
        int remote_reply = 0;
        char **fwd_reply;
        int fwd_list_index = 0;

        //data structures for forwarding interests
        struct ndn_charbuf *name_fwd = ndn_charbuf_create();
        struct ndn_charbuf *data_packet = ndn_charbuf_create();
        int fwd_message_length = 0;
//        int num_reply=0;
        //int new_interest_random_comp = 0;
        //char *new_interest_name = NULL;

        return_data.num_message = 0;
        unsigned char *buffer = NULL;
        unsigned char *reset_buffer = NULL;
        int iter = 0;
        size_t buffer_len = 0;

        //max num threads
        int num_threads = 256;

        //get the interest name and random component from incoming packet
        res = find_interest_name(info->interest_ndnb, info->pi, &interest_name,
                                 &interest_rand_str, &forward_path);
        if (res !=0) {
            fprintf(logfile, "Could not parse interest name\n");
            fclose(logfile);
            break;
        }
        fprintf(logfile, "Interest name %s, random is %s forward_path is %s \n", interest_name, interest_rand_str, forward_path);
        fflush(logfile);
#ifdef DEBUG
        printf("Interest name %s, random is %s forward_path is %s \n", interest_name, interest_rand_str, forward_path);
#endif

        //check for duplicate random number and looping interest
        //drop if duplicate
        res = check_duplicate_interests(interest_name, interest_rand_str, forward_path);
        if (res == 1) {
            fprintf(logfile, "Dropping duplicate interest %s%s%s\n", interest_name, slash, interest_rand_str);
            break;
        }

        //get the matching faces for this interest
        res = get_faces(interest_name, faces, &number_faces, &longest_prefix, &matching_fib_entry);

#ifdef DEBUG
        for (i=0; i <number_faces; i++) {
            fprintf(logfile, "face %s is %s\n", faces[i], longest_prefix);
            printf("face %s is %s\n", faces[i], longest_prefix);
            fflush(logfile);
        }
#endif

        //there is no such face, there is no route
        if (number_faces == 0) {
            return_data.num_message = 1;
            return_data.message_length =  malloc(sizeof(uint32_t) * 1);
            if (return_data.message_length == NULL) {
                fprintf(logfile, "Can not allocate memory for reply message, field 1\n");
                fclose(logfile);
                exit(1);
            }
#ifdef DEBUG
            printf("No route found\n");
#endif
            //replay appropriately
            return_data.message_length[0] = strlen(node_id)+1 + strlen(":NO ROUTE FOUND") ;
            return_data.fwd_message = malloc(sizeof(char *) * 1);
            return_data.fwd_message[0] = malloc(strlen(node_id)+1 + strlen(":NO ROUTE FOUND"));
            if (return_data.fwd_message == NULL|| return_data.fwd_message[0] == NULL) {
                fprintf(logfile, "Can not allocate memory for reply message, data\n");
                fclose(logfile);
                exit(1);
            }
            sprintf(return_data.fwd_message[0], "%s%s",  node_id, ":NO ROUTE FOUND");
        }

        //we have some faces, find if they are remote or local
        else {
            //get the number of remote ips
            res = find_remote_ip(faces, number_faces, remote_ips, &num_remote_ips);
#ifdef DEBUG
            printf("Number of remote IP %d\ninterest_name %s length: %zu\nlongest_prefix %s length %zu\nmatching fib_entry %s length %zu\n", num_remote_ips, interest_name, strlen((const char *)interest_name), longest_prefix, strlen((const char *)longest_prefix), matching_fib_entry, strlen((const char *)matching_fib_entry));
#endif

            fprintf(logfile, "Number of remote IP %d\ninterest_name %s length: %zu\nlongest_prefix %s length %zu\nmatching fib_entry %s length %zu\n", num_remote_ips, interest_name, strlen((const char *)interest_name), longest_prefix, strlen((const char *)longest_prefix), matching_fib_entry, strlen((const char *)matching_fib_entry));
            fflush(logfile);


            //if no remote ip found, this is local
            if (num_remote_ips == 0) {
                //does the name matches with longest prefix(without ndnx:)? otherwise, no such content
                if (strcmp((const char *)interest_name, (const char *)matching_fib_entry+5) == 0) {
#ifdef DEBUG
                    printf("This is local\n");
#endif
                    fprintf(logfile, "This is local\n");
                    fflush(logfile);
                    //reply appropriately
                    return_data.num_message = 1;
                    return_data.message_length =  malloc(sizeof(uint32_t) * 1);
                    return_data.message_length[0] = strlen(node_id)+1 + strlen(":LOCAL") ;
                    return_data.fwd_message = malloc(sizeof(char *) * 1);
                    return_data.fwd_message[0] = malloc(strlen(node_id)+1 + strlen(":LOCAL"));
                    sprintf(return_data.fwd_message[0], "%s%s",  node_id, ":LOCAL");
                }

                //else, no such content
                else {
                    return_data.num_message = 1;
                    return_data.message_length =  malloc(sizeof(uint32_t) * 1);
                    if (return_data.message_length == NULL) {
                        fprintf(logfile, "Can not allocate memory for reply message, field 1\n");
                        fclose(logfile);
                        exit(1);
                    }
                    printf("No such content \n");
                    //reply appropriately
                    return_data.message_length[0] = strlen(node_id)+1 + strlen(":NO SUCH CONTENT") ;
                    return_data.fwd_message = malloc(sizeof(char *) * 1);
                    return_data.fwd_message[0] = malloc(strlen(node_id)+1 + strlen(":NO SUCH CONTENT"));
                    if (return_data.fwd_message == NULL|| return_data.fwd_message[0] == NULL) {
                        fprintf(logfile, "Can not allocate memory for reply message, data\n");
                        fclose(logfile);
                        exit(1);
                    }
                    sprintf(return_data.fwd_message[0], "%s%s",  node_id, ":NO SUCH CONTENT");
                }
                free(matching_fib_entry);
            }
            //we found some remote ips for this face
            else {
                struct thread_reply *p_thread_reply;
                forwarding_threads = malloc((num_threads) * sizeof (pthread_t));
                struct pass_thread_args args[num_threads];
                int i;

                //pack args for passing to threads
                for(i=0; i< num_remote_ips; i++) {
                    args[i].p_thread_id = i;

                    args[i].p_interest_name = calloc(strlen(interest_name) + 1, sizeof(char));
                    strncpy(args[i].p_interest_name, interest_name, strlen(interest_name));

                    args[i].p_interest_random_str = calloc(strlen(interest_rand_str) + 1, sizeof(char));
                    strncpy(args[i].p_interest_random_str, interest_rand_str, strlen(interest_rand_str));

                    args[i].p_forward_path = calloc(strlen(forward_path) + 1, sizeof(char));
                    strncpy(args[i].p_forward_path, forward_path, strlen(forward_path));

                    args[i].p_remote_ip = calloc(strlen(remote_ips[i]) + 1, sizeof(char));
                    strncpy(args[i].p_remote_ip, remote_ips[i], strlen(remote_ips[i]));

                    //create threads
                    if (pthread_create(&forwarding_threads[i], NULL, get_fwd_reply, (void *)&args[i]) != 0) {
                        fprintf(logfile, "Error creating thread!\n");
                        fflush(logfile);
                        break;

                    }

                }

                fwd_reply = malloc(1000 * sizeof(char *));
                for (remote_ip_index = 0; remote_ip_index<num_remote_ips; remote_ip_index++) {
                    int ret = pthread_join(forwarding_threads[remote_ip_index],(void **)&p_thread_reply);
                    //printf("Pthread reply %d\n", p_thread_reply->status_code);
                    if(ret == 0) {
                        if ( p_thread_reply->status_code == 1) {
                            //    fprintf(logfile, "Duplicate interest %s%s%s\n", interest_name, slash, interest_rand_str);
                            break;
                        } 
						else {
                            for (remote_reply=0; remote_reply < p_thread_reply->num_reply; remote_reply++) {
#ifdef DEBUG
                                printf("%d of %d: reply in main %s\n",  remote_reply+1 ,p_thread_reply->num_reply,p_thread_reply->reply[remote_reply]);
#endif
                                fwd_reply[fwd_list_index] = calloc(strlen(p_thread_reply->reply[remote_reply])+1, sizeof(char));
                                strncpy(fwd_reply[fwd_list_index], p_thread_reply->reply[remote_reply],strlen(p_thread_reply->reply[remote_reply]));
                                fwd_list_index++;
                            }
                        }
                        free (p_thread_reply);
                    } 
					else {
                        fprintf(logfile, "Can not get reply from thread %s%s%s\n", interest_name, slash, interest_rand_str);
                        continue;
                    }
                }
                printf("\n\n");
                for (i = 0; i < fwd_list_index; i++) {
                    fprintf(logfile, "Reply is %s \n", fwd_reply[i]);
#ifdef DEBUG
                    printf("Reply main is %s \n\n", fwd_reply[i]);
#endif
                }

                //process and store the replies in a data packet
                return_data.num_message = fwd_list_index;
                return_data.message_length =  (uint32_t*) calloc (return_data.num_message,sizeof(uint32_t));
                if (return_data.message_length == NULL) {

                    fprintf(logfile, "Can not allocate memory for reply message leangth\n");
                    fclose(logfile);
                    exit(1);
                }

                //store the messages
                return_data.fwd_message = malloc(return_data.num_message*sizeof(char *));
                for (i = 0; i < fwd_list_index; i++) {
                    return_data.message_length[i] = strlen(node_id) + strlen("~")+ strlen(fwd_reply[i]) + 1;
                    return_data.fwd_message[i] = malloc(strlen(node_id) +  strlen("~")+ strlen(fwd_reply[i]) + 1);
                    if (return_data.fwd_message[i] == NULL) {
                        fprintf(logfile, "Can not allocate memory for reply message number %d\n", i);
                        fclose(logfile);

                        exit(1);
                    }
                    sprintf(return_data.fwd_message[i], "%s%s%s",  node_id, "~", fwd_reply[i]);
#ifdef DEBUG
                    fprintf(logfile, "%s\n", return_data.fwd_message[i]);
                    fflush(logfile);
#endif
                }
            }

        }

        //}//remove
        //now we have the messages, pack them and send them back
        fprintf(logfile, "return_data.num_message = %d\n", return_data.num_message);
        fflush(logfile);

        for (iter = 0; iter<return_data.num_message; iter++) {
            fprintf(logfile, "message length = %d\n", return_data.message_length[iter]);
            fprintf(logfile, "message = %s\n", return_data.fwd_message[iter]);
            fflush(logfile);
            fwd_message_length += return_data.message_length[iter];
        }

        //pack the buffer for sending
        buffer = malloc(sizeof(uint32_t)* (1+ return_data.num_message) + fwd_message_length);
        if (buffer == NULL) {
            fprintf(logfile, "Can not allocate memory for return buffer %d\n", i);
            fclose(logfile);

            exit(1);
        }

        //we have to reset the pointer before sending
        reset_buffer = buffer;

        //copy num_fwd_interest
        memcpy(buffer, &return_data.num_message, sizeof(uint32_t));

        buffer += sizeof(uint32_t);
        buffer_len += 1*sizeof(uint32_t);

        //copy the lengths
        for (iter = 0; iter<return_data.num_message; iter++) {
            memcpy(buffer, &return_data.message_length[iter], sizeof(uint32_t));
            buffer += sizeof(uint32_t);
            buffer_len += sizeof(uint32_t);
        }

        //copy the strings
        for (iter = 0; iter<return_data.num_message; iter++) {
            memcpy(buffer, return_data.fwd_message[iter], return_data.message_length[iter]);
            buffer += return_data.message_length[iter];
            buffer_len += return_data.message_length[iter];
            //free(return_data.fwd_message[iter]);
        }

        //reset pointer
        buffer = reset_buffer;

        //send data packet
        construct_trace_response(info->h, data_packet, info->interest_ndnb, info->pi, buffer, buffer_len);
        res = ndn_put(info->h, data_packet->buf, data_packet->length);
        printf("\n");
//free all the allocate memory     1169
        ndn_charbuf_destroy(&data_packet);
        ndn_charbuf_destroy(&name_fwd);
        free((void*)interest_name);
        free((void*)forward_path);
        free((void *)longest_prefix);
        free(return_data.fwd_message);
        free(buffer);
    }

//    return NDN_UPCALL_FINAL;
    break;

    case NDN_UPCALL_INTEREST_TIMED_OUT:
        fprintf(logfile, "request timed out - retrying\n");

        fflush(logfile);
        return NDN_UPCALL_RESULT_REEXPRESS;

    case NDN_UPCALL_CONTENT_UNVERIFIED:
        fprintf(logfile, "Could not verify content");
        fflush(logfile);
        return NDN_UPCALL_RESULT_ERR;

    case NDN_UPCALL_CONTENT_BAD:
        fprintf(logfile, "Bad content\n");
        fflush(logfile);
        return NDN_UPCALL_RESULT_ERR;

    default:
        fprintf(logfile, "Unexpected response\n");
        fflush(logfile);
        return NDN_UPCALL_RESULT_ERR;
    }
    return NDN_UPCALL_FINAL;
}

void usage(void) {
    ///prints the usage and exits
    printf("%s version %s \n", SRV_PROGRAM, SRV_VERSION);
    printf("%s \n\n", SRV_PROGRAM);

    printf("  -h             print this help and exit\n");
    printf("  -V             print version and exit\n\n");
    exit(0);
}


int main(int argc, char **argv) {

    //no argument necessary
    if (argc != 1) {
        usage();
        exit(1);
    }


    //check ndn_path
    if (NDN_DIR[strlen(NDN_DIR) - 1] != '/') {
        printf("Please provide NDNx path with a trailing slash\n");
        exit(1);
    }

    //check if logfile is present, if yes, open in append mode
    //write mode otherwise

    logfile = fopen(LOGFILE, "r");
    if (logfile != NULL) {
        fclose(logfile);
        log_exist = 1;
    }

    if (log_exist == 1) {
        logfile = fopen(LOGFILE, "a");
    } else {
        logfile = fopen(LOGFILE, "w");
    }


    //seed the random
    srand ((unsigned int)time (NULL)*getpid());

    //get the node_id, IP address for now
    if (get_ip_addresses(node_id) == NULL) {
        printf("Can not get node_id\n");
        fprintf(logfile, "Can not get node_id\n");
        fclose(logfile);
        exit(1);
    }
    //print node id
    printf("Node ID:%s\n", node_id);

    //create ndn handle
    struct ndn *ndn = NULL;

    //connect to ndnd
    ndn = ndn_create();
    if (ndn_connect(ndn, NULL) == -1) {
        fprintf(logfile, "Could not connect to ndnd");
        fclose(logfile);
        exit(1);
    }

    //create prefix we are interested in, register in FIB
    int res;
    struct ndn_charbuf *prefix = ndn_charbuf_create();

    //We are interested in anythin starting with /trace
    res = ndn_name_from_uri(prefix, "/trace");
    if (res < 0) {
        fprintf(logfile, "Can not convert name to URI\n");
        fclose(logfile);
        exit(1);
    }

    //handle for upcalls, receive notifications of incoming interests and content.
    //specify where the reply will go
    struct ndn_closure in_interest = {.p = &incoming_interest};
    in_interest.data = &prefix;

    //set the interest filter for prefix we created
    res = ndn_set_interest_filter(ndn, prefix, &in_interest);
    if (res < 0) {
        fprintf(logfile, "Failed to register interest (res == %d)\n", res);
        fclose(logfile);
        exit(1);
    }

    //listen infinitely
    res = ndn_run(ndn, -1);

    //cleanup
    ndn_destroy(&ndn);
    ndn_charbuf_destroy(&prefix);
    exit(0);
}
