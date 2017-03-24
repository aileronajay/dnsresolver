Dependencies
------------------------------------------------------------
--> Python 2.7.12 is used for running the mydig.py and mydigsecure.py
--> it expects the modules dnspython and pycrypto to be accessible to python
--> The code expects unrestricted connectivity to the dns root servers



Running the programs
------------------------------------------------------------
The syntax for running these files is

python mydig.py domain_to_query dns_information_type

where domain_to_query is the domain that you to query for example www.google.com.
dns_information_type is the dns information type that you want. It may be of the 
form A, MX or NS

A sample query is

python mydig.py www.google.com A


