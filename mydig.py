import sys


import dns.message
import dns.rdtypes
import dns.rdatatype
import dns.query
import dns.rrset
import dns.flags
import multiprocessing
import time

# to get ip address for the dns server
def helper_function(domain_query, 
                    server_to_connect):
    reply =  dns.query.udp(dns.message.make_query(domain_query,dns.rdatatype.A),str(server_to_connect))

    if(reply.answer):
        return reply.answer[0][0]
    else:
        #here we are always taking the first nameserver in the additional list
        # the reply.additional gives a list of RRSets, hence querying reply.additional[0] returns the first element
        # in that list. Once we have a RRSet object, it is a set containing ip addresses
        #new_server_to_connect = reply.additional[0][0]
        new_server_to_connect = None
        for elem in reply.additional:
            if dns.rdatatype.to_text(elem.rdtype) == 'A':
                new_server_to_connect = elem[0]
                    #print '\n', new_server_to_connect;
                break;
        return helper_function(domain_query, new_server_to_connect)


def find_ip_address_queue_wrapper(domain_query, server_to_connect,
                                                               query_mode,root_server,q):

    reply = find_ip_address(domain_query, server_to_connect, query_mode,root_server)
    q.put(reply)




def find_ip_address_preprocess(domain_query, server_to_connect, root_server, query_type=None):

    all_root_servers = ["198.41.0.4","192.228.79.201","192.33.4.12","199.7.91.13",
                   "192.203.230.10","192.5.5.241","192.112.36.4","198.97.190.53","192.36.148.17"
                   ,"192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"];


    query_mode = dns.rdatatype.A
    if(query_type == 'MX') :
        query_mode = dns.rdatatype.MX
    if(query_type == 'NS'):
        query_mode = dns.rdatatype.NS
    #response = find_ip_address(domain_query=domain_query, server_to_connect=server_to_connect
    #                , query_mode=query_mode, root_server=root_server)

    for root_server in all_root_servers:
        q = multiprocessing.Queue()
        p = multiprocessing.Process(target=find_ip_address_queue_wrapper, args = (domain_query, server_to_connect,
                                                               query_mode,root_server,q))
        print 'trying root server ',root_server
        p.start()
        p.join(5)
        if p.is_alive():
            p.terminate()
            p.join()
        else:
            #print ('in the else block')
            response = q.get_nowait()
            if response:
                print response;
                break;

def find_ip_address(domain_query, 
                    server_to_connect, query_mode, root_server):

    request = dns.message.make_query(domain_query,query_mode);
    #print '\n', request, server_to_connect

    reply =  dns.query.udp(request,str(server_to_connect))

    #print '\n',request, server_to_connect, reply

    #print reply
    #possibly refactor code to create a separate method for NS processing to prevent an IF check everytime
    if(query_mode == dns.rdatatype.NS):
        #checking if the server is authoritative, as there is no answer section for NS message
        if("AA" in dns.flags.to_text(reply.flags)):
            return reply

    #print reply

    if(reply.answer):
        if(dns.rdatatype.to_text(reply.answer[0].rdtype) == 'CNAME'):
            #print 'reached cname', reply.answer[0][0]
            return find_ip_address(domain_query=reply.answer[0][0].to_text(),
                            server_to_connect= root_server,
                            query_mode= query_mode,
                            root_server= root_server)
        else:
            return reply
    else:
        if(reply.additional):
            #here we are always taking the first nameserver in the additional list
            # the reply.additional gives a list of RRSets, hence querying reply.additional[0] returns the first element
            # in that list. Once we have a RRSet object, it is a set containing ip addresses
            #new_server_to_connect = reply.additional[0][0]

            new_server_to_connect = None
            for elem in reply.additional:
                if dns.rdatatype.to_text(elem.rdtype) == 'A':
                    new_server_to_connect = elem[0]
                    #print '\n', new_server_to_connect;
                    break;

            return find_ip_address(domain_query, new_server_to_connect, query_mode, root_server)
        else:
            # there is no data in reply and additional fields
            # in a scenario such as google.co.jp. In this scenario, we take the name server from authority
            # field, find the ip address for the name server using helper_function and redirect the query to
            # the name server
            
            if(dns.rdatatype.to_text(reply.authority[0].rdtype) == 'SOA'):
                if query_mode == dns.rdatatype.MX:
                    #print reply;
                    return reply;

            name_server = reply.authority[0][0]
            new_server_to_connect = helper_function(domain_query=name_server.to_text(), server_to_connect=root_server)
            return find_ip_address(
                domain_query = domain_query, 
                server_to_connect = new_server_to_connect, 
                root_server = root_server,
                query_mode = query_mode)

domain_query = sys.argv[1]
query_type = sys.argv[2]

dns_server = "192.228.79.201"
#domain_query = "a1165.dscg.akamai.net"
#domain_query = "www.cs.stp.edu"
#domain_query
#query_type = None
#domain_query = "www.upenn.edu"
find_ip_address_preprocess(domain_query= domain_query, server_to_connect=dns_server,root_server= dns_server,query_type=query_type)