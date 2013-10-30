char* get_ip_addresses(char *node_id)                                                      
{                                                                               
    /*************************************************************************/ 
    ///This function returns one IP address of the node it is running on. This   
    ///IP address (IPv4 or IPv6) is used as a node identifier for NDN trace. 
    //Note that IP address here is just an identifier and can be replaced by 
    //any other unique node identifier.                                              
    /*************************************************************************/ 
    struct ifaddrs *ip_addr, *ifa;                                              
    struct sockaddr_in *ipv4;                                                   
    int res;                                                                    
    const char* result;                                                         
    char buffer[128];                                                           
                                                                                
    //get the ip addresses                                                      
    res = getifaddrs(&ip_addr);                                                 
    if (res != 0)                                                               
    {                                                                           
        fprintf(stderr, "cannot get addresses");                                
        exit(1);                                                                
    }                                                                           
                                                                                
    //iterate over IP addresses                                                 
    for (ifa = ip_addr; ifa != NULL; ifa = ifa->ifa_next)                       
    {                                                                           
        //ignore if interface has no address or loopback address                
        if (ifa->ifa_addr == NULL)                                              
            continue;                                                           
                                                                                
        //get node id from IPv4 addresses                                       
        if (ifa->ifa_addr->sa_family == AF_INET)                                
        {                                                                       
            ipv4 = (struct sockaddr_in *)(ifa->ifa_addr);                       
            result = inet_ntop(ifa->ifa_addr->sa_family, (void *)&(ipv4->sin_addr), buffer, sizeof(buffer));
                                                                                
            //there is no IPv4 address                                          
            if(result == 0)                                                     
            {                                                                   
                fprintf(stderr, "Can not get IP address");                      
                exit(1);                                                        
            }                                                                   
                                                                                
            //loopback can not be an identifier                                 
            else if(strcmp(buffer, "127.0.0.1")==0) continue;                   
                                                                                
            //else, we just found an identifier, return it                      
            else                                                                
            {                                                                   
                #ifdef DEBUG                                                    
                    printf("Identifier(IPv4)%s\n", buffer);                     
                #endif                                                          
                strncpy(node_id, buffer, strlen(buffer));                       
                freeifaddrs(ip_addr);                                                       
                return(node_id);                                                      
            }                                                                   
        }                                                                       
    }
                                                                                
    ///Did not find any IP, return NULL
    return(NULL);                                                                  
}
