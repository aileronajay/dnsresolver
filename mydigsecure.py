## need to verify dns keys for a level using ds of the previous level
# need to verify the ds of a level using using dnskey of the same level, go to the next level

import dns.message
import dns.rdtypes
import dns.rdatatype
import dns.query
import dns.rrset
import dns.dnssec
import dns.rdtypes.dnskeybase
import sys
import multiprocessing
import time
#import dns.dnssec.ValidationFailure

# to get ip address for the dns server
def helper_function(domain_query, 
                    server_to_connect):
    reply =  dns.query.udp(dns.message.make_query(domain_query,dns.rdatatype.A),str(server_to_connect))
    
    print reply

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
        return helper_function(domain_query, new_server_to_connect)



def resolve_securely(query_domain, server_to_connect, domain_for_dns_query, previous_ds, root_server, query_type ):
    if(previous_ds == None):
        # processing for the root server
        
        domain_to_query_dns = dns.name.from_text('.')
        
        dnskey_request_msg = dns.message.make_query(domain_to_query_dns,dns.rdatatype.DNSKEY);
        dnskey_request_msg.want_dnssec(wanted=True)
        dnskey_reply =  dns.query.tcp(dnskey_request_msg,server_to_connect)
        
        #print '\n'*3,dnskey_request_msg,'\n'*2, dnskey_reply
        
        
        for a in dnskey_reply.answer:
            if(dns.rdatatype.to_text(a.rdtype) == 'DNSKEY'):
                dns_key_element = a;
            else:
                rrsig_element = a;
        
        #validate the DNSKEY retrieved (the root level key is self signed)
        try:
            dns.dnssec.validate(dns_key_element, rrsig_element,{domain_to_query_dns:dns_key_element})
        except ValidationFailure:
            return "Failure at root : DNSKEY RRSet validation failed , DNSSEC is configured but the digital signature could NOT be verified";
            #return;
        
        #now make the actual query
        act_request_msg = dns.message.make_query(query_domain,query_type);
        act_request_msg.want_dnssec(wanted=True)
        act_reply =  dns.query.tcp(act_request_msg,server_to_connect)
        
        #get the ds and rrsig and validate
        for elem in act_reply.authority:
            rrset_type = dns.rdatatype.to_text(elem.rdtype) 
            next_dns_domain = elem.name
            if(rrset_type == 'DS'):
                act_reply_ds = elem
            if(rrset_type == 'RRSIG'):
                act_reply_ds_rrsig = elem
        
        next_server_to_connect = act_reply.additional[0][0]
        
        #validate the signed ds with the message that we have
        try:
            dns.dnssec.validate(act_reply_ds, act_reply_ds_rrsig,{domain_to_query_dns:dns_key_element})
        except ValidationFailure:
            return "Failure at root: DS RRSet validation failed, DNSSEC is configured but the digital signature could NOT be verified";
            #return;
        
        #get next ip address to go to make the call
        return resolve_securely(
            query_domain = query_domain,
            server_to_connect = next_server_to_connect,
            domain_for_dns_query = next_dns_domain, 
            previous_ds = act_reply_ds, 
            root_server = root_server, 
            query_type = query_type);
    
    #processing for servers downstream from the root server
    else:
        dnskey_request_msg = dns.message.make_query(str(domain_for_dns_query),dns.rdatatype.DNSKEY);        
        dnskey_request_msg.want_dnssec(wanted=True)
        dnskey_reply =  dns.query.tcp(dnskey_request_msg,str(server_to_connect))
        
        #print "after";
        
        #print '\n'*3,dnskey_request_msg,'\n'*2, server_to_connect, dnskey_reply, 
        
        for a in dnskey_reply.answer:
            if(dns.rdatatype.to_text(a.rdtype) == 'DNSKEY'):
                dns_key_element = a;
            else:
                rrsig_element = a;
        
        dns_key_validated = None;        
        ds_hash_algo = previous_ds[0].digest_type
        
        if(ds_hash_algo == 1):
            hash_algo = "SHA1"
        else:
            hash_algo = "SHA256"
        
        for dns_key in dns_key_element:            
            ds_from_key = dns.dnssec.make_ds(domain_for_dns_query, dns_key ,hash_algo);
            if(ds_from_key == previous_ds[0]):
                dns_key_validated = True;
                break;

        if(not dns_key_validated):
            return "Failure: DNS key validation using prev ds failed, DNSSEC is configured but the digital signature could NOT be verified";
            #return;
        
        #validate the dnskey rrset using the validated SEP key
        try:
            dns.dnssec.validate(dns_key_element, rrsig_element,{domain_for_dns_query:dns_key_element})
        except ValidationFailure:
            return("Failure: DNSKEY validation failed, DNSSEC is configured but the digital signature could NOT be verified");
            #return;
        
        #make an actual request now    
        act_request_msg = dns.message.make_query(query_domain,query_type);
        act_request_msg.want_dnssec(wanted=True)
        act_reply =  dns.query.tcp(act_request_msg,str(server_to_connect))
        
        #print '\n',act_request_msg, server_to_connect
        
        #print '\n',act_reply
        
        #if we have a response stop
        if(act_reply.answer):
            #cname case
            if(dns.rdatatype.to_text(act_reply.answer[0].rdtype) == 'CNAME'):
                #TODO validate cname record, add validation code
                return resolve_securely(query_domain= act_reply.answer[0][0].to_text(),
                                server_to_connect= root_server,
                                domain_for_dns_query= None,
                                previous_ds= None,
                                root_server = root_server,
                                query_type = query_type);
            else:
                return act_reply;
            #if the response is cname, we need to continue searching
            ##return;
        
        if(act_reply.additional):
            secure_absence_confirmation = None;
            #get the ds and rrsig and validate
            for elem in act_reply.authority:
                rrset_type = dns.rdatatype.to_text(elem.rdtype) 
                next_dns_domain = elem.name
                #print rrset_type
                if(rrset_type == 'DS'):
                    act_reply_ds = elem
                if(rrset_type == 'RRSIG'):
                    act_reply_ds_rrsig = elem
                if(rrset_type in ['NSEC','NSEC3']):
                    secure_absence_confirmation = True;
                    act_reply_nsec = elem;
                # implement NSEC3 and NSEC logic here? have already implemented below!

            if(secure_absence_confirmation):
                try:
                    dns.dnssec.validate(act_reply_nsec, act_reply_ds_rrsig,{domain_for_dns_query:dns_key_element})
                except ValidationFailure:
                    return ("Failure: NSEC data validation failed, DNSSEC not supported");
                #print('Failure : DNSSEC record is missing ');
                #print act_reply;
                return 'Failure : DNSSEC record is missing, DNSSEC not supported ';

            next_server_to_connect = act_reply.additional[0][0]

            #validate the signed ds with the message that we have
            try:
                dns.dnssec.validate(act_reply_ds, act_reply_ds_rrsig,{domain_for_dns_query:dns_key_element})
            except ValidationFailure:
                return "Failure: DS data validation failed, DNSSEC is configured but the digital signature could NOT be verified";
                #return;
            return resolve_securely(query_domain =query_domain,
                             server_to_connect = next_server_to_connect,
                             domain_for_dns_query = next_dns_domain, 
                             previous_ds = act_reply_ds, 
                             root_server = root_server,
                             query_type = query_type);
        #else block, reply is empty, additional is empty
        else:
            
            #check if we have a SOA record, if yes return
            if(dns.rdatatype.to_text(act_reply.authority[0].rdtype) == 'SOA'):
                #if query_mode == dns.rdatatype.MX:
                    #print reply;
                return act_reply;
            
            name_server = act_reply.authority[0][0]
            new_server_to_connect = helper_function(domain_query=name_server.to_text(), server_to_connect=root_server)
            
            for elem in act_reply.authority:
                rrset_type = dns.rdatatype.to_text(elem.rdtype) 
                next_dns_domain = elem.name
                #print rrset_type
                if(rrset_type == 'DS'):
                    act_reply_ds = elem
                if(rrset_type == 'RRSIG'):
                    act_reply_ds_rrsig = elem
            try:
                dns.dnssec.validate(act_reply_ds, act_reply_ds_rrsig,{domain_for_dns_query:dns_key_element})
            except ValidationFailure:
                return "Failure: DS data validation failed, DNSSEC is configured but the digital signature could NOT be verified";
                #return;
            
            return resolve_securely(query_domain =query_domain,
                             server_to_connect = new_server_to_connect,
                             domain_for_dns_query = next_dns_domain, 
                             previous_ds = act_reply_ds, 
                             root_server = root_server,
                             query_type = query_type);


#query_domain = "www.upenn.edu"
#query_domain = "opend"
#query_domain = "www.opendnssec.org" #works end to end
#query_domain = "www.cnn.com" #works end to end
#query_domain = "www.ietf.org" #works end to end
#query_server = "192.228.79.201";
#domain_to_query_dns = None;
#resolve_securely(
#    query_domain=str(query_domain), 
#    server_to_connect = str(query_server), 
#    domain_for_dns_query = None,
#    previous_ds = None,
#    root_server = query_server,
#    query_type = dns.rdatatype.MX
#);

def find_ip_address_securely_queue_wrapper(query_domain, server_to_connect, domain_for_dns_query, previous_ds, 
                                           root_server, query_type ,q):

    #reply = resolve_securely(domain_query, server_to_connect, query_mode,root_server)
    #resolve_securely(
    reply = resolve_securely(query_domain=str(query_domain), 
                             server_to_connect = str(server_to_connect), 
                             domain_for_dns_query = domain_for_dns_query,
                             previous_ds = previous_ds,
                             root_server = root_server,
                             query_type = query_type)
    q.put(reply)


def find_ip_address_securely_preprocess(domain_query, query_type=None):

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
        p = multiprocessing.Process(target=find_ip_address_securely_queue_wrapper, 
                                    args = (domain_query, 
                                            root_server,
                                            None,
                                            None,
                                            root_server,
                                            query_mode
                                            ,q))
        print 'trying root server ',root_server
        p.start()
        p.join(15)
        if p.is_alive():
            p.terminate()
            p.join()
        else:
            #print ('in the else block')
            response = q.get_nowait()
            if response:
                print response;
                break;

query_domain = sys.argv[1]
query_type = sys.argv[2]
#query_domain = "www.opendnssec.org"
#query_domain = "www.opendnssec.org"
#query_type = "MX"
#query_domain = "www.opendnssec.org"
#query_server = "192.228.79.201"
find_ip_address_securely_preprocess(query_domain, query_type)
#ret_value = resolve_securely(
#    query_domain=str(query_domain), 
#    server_to_connect = str(query_server), 
#    domain_for_dns_query = None,
#    previous_ds = None,
#    root_server = query_server,
#    query_type = dns.rdatatype.A
#);
#print ret_value

