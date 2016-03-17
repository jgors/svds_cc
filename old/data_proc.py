#!/usr/bin/env python

#----------------------------------------------------------------
# Author: Jason Gors <jasonDOTgorsATgmail>
# Creation Date: 03-14-2016
# Purpose:
#----------------------------------------------------------------
'''
pip install xxx --user --upgrade

python-geoip
python-geoip-geolite2
ipwhois
apache_log_parser
cymruwhois
'''
'''
This is perfect...gives everything:
http://ip-api.com/docs/api:json
'''

'''
Schema:
-------
They use nginx (from checking the server in the headers of a request)
(is like the "Combined Log Format" -- http://httpd.apache.org/docs/trunk/logs.html#accesslog)

198.0.200.105 - - [14/Jan/2014:09:36:50 -0800] "GET /svds.com HTTP/1.1" 301 241 "http://www.svds.com/rockandroll/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36"

1. Remote host (ie the client IP):                                     198.0.200.105
2. Identity of the user determined by identd:                          -       (the 1st hyphen is the identd_clientid)
    (not usually used since not reliable)
3. User name determined by HTTP authentication:                        -       (the 2nd hyphen is the userid -- If the status code for the request is 401, then this value should not be trusted because the user is not yet authenticated.  If the document is not password protected, this part will be "-" just like the previous one.
4. Time the server finished processing the request:                    [14/Jan/2014:09:36:50 -0800]        (??? docs say, "The time that the request was received." not "finished processing")
5. Request line from the client. ("GET / HTTP/1.0"):                   "GET /svds.com HTTP/1.1"
    - method:                                 GET                       GET
    - the client requested the resource:      /                         /svds.com
    - protocol:                               HTTP/1.0                  HTTP/1.1
6. Status code sent from the server to the client (200, 404 etc.):     301
7. Size of the response to the client (in bytes):                      241
8. Referer is the page that linked to this URL:                        "http://www.svds.com/rockandroll/"      (This gives the site that the client reports having been referred from. (This should be the page that links to or includes /apache_pb.gif))
9. User-agent is the browser identification string:                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36"



Write out to access_log.out the following:
-----------------------------------------------
date & time request was processed by the web server as epoch (from the file)
uri user click on (from the file)
referer (from the file)
ip address (from the file)
organization (from the ip address)
latitude (from the ip address)
longitude (from the ip address)
isp name (from the ip address)

###########################
So for their Schema example:
198.0.200.105 - - [14/Jan/2014:09:36:50 -0800] "GET /svds.com HTTP/1.1" 301 241 "http://www.svds.com/rockandroll/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36"

(From the file)
date & time request was processed by the web server as epoch:   [14/Jan/2014:09:36:50 -0800]
uri user clicked on:    /svds.com
referer:    http://www.svds.com/rockandroll/
ip address:     198.0.200.105

(From the ip address)
organization:
latitude:
longitude:
isp name:
###########################
'''
from os import path
import re
import shelve

import ipwhois
from ipwhois import IPWhois
from apache_log_parser import make_parser
from cymruwhois import Client
from geoip import geolite2



def parse_log(log):
    '''
    NOTE: log files may contain information supplied directly by the client, without escaping. Therefore,
    it is possible for malicious clients to insert control-characters in the log files, so care must be
    taken in dealing with raw logs. See,
    http://httpd.apache.org/docs/trunk/logs.html#security
    '''

    parts = [
        r'(?P<host>\S+)',                   # remote host %h
        r'\S+',                             # identity of the user %l (unused)
        r'(?P<username>\S+)',               # user name %u
        r'\[(?P<timestamp>.+)\]',           # time %t

        r'"(?P<request>.+)"',               # request for client "%r"
        #  get out the uri from the request:   r'.+GET (?P<url>\/(?P<method>.+?)\?.+).+HTTP\/1\.1" (?P<statuscode>\d{3})'

        r'(?P<status>[0-9]+)',              # status code %>s
        r'(?P<size>\S+)',                   # size of response %b (NOTE can be '-')
        r'"(?P<referer>.*)"',               # referer "%{Referer}i"
        r'"(?P<useragent>.*)"',             # user-agent "%{User-agent}i"
    ]

    pattern = re.compile(r'\s+'.join(parts) + r'\s*\Z')

    m = pattern.match(log)
    res = m.groupdict()

    if res["referer"] == "-":
        res["referer"] = None

    return res

    # if res["username"] == "-":
        # res["username"] = None
    # res["status"] = int(res["status"])
    # if res["size"] == "-":
        # res["size"] = 0
    # else:
        # res["size"] = int(res["size"])



def parse_log2(log):
    apache_combined_format = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
    # line_parser = apache_log_parser.make_parser(apache_combined_format)
    line_parser = make_parser(apache_combined_format)
    log_data = line_parser(log)
    return log_data


# def convert_time_to_epoch():
    # pass

ip_names = open('./ip_names.txt', 'w')
# addresses = open('./addresses.txt', 'w')


def use_ip_to_get_isp(ip):
    ''' This might be redundant on the previous ip lookup, but the owner output
        seems to have a might better consistenciy
    '''
    c = Client()    # should probably pull this out of here so not to create it each time
    r = c.lookup(ip)
    # print r.asn
    # print r.owner
    return {'isp_name': r.owner}
    # return (r.asn, r.owner)


# def get_lat_and_long(location):
    # ''' NOTE could use google maps api to get this by using
        # the address pulled out from the whois call
    # '''
    # pass


def get_lat_and_long(ip):
    match = geolite2.lookup(ip)
    nada = (None, None)
    if match:
        loc = match.location
        if loc:
            return loc
        else:
            return nada
    else:
        return nada
    # NOTE maybe timezone could be useful for converting the time to the epoch


ip = '198.0.200.105'
# ip = '108.223.242.32'

def get_ip_info(ip):
    '''maxmind:  IP database - Determine the Internet Service Provider,
                 Registering Organization, and AS Number associated with an IP address

    obj.lookup_rdap() returns
        :query: The IP address (String)
        :asn: The Autonomous System Number (String)
        :asn_date: The ASN Allocation date (String)
        :asn_registry: The assigned ASN registry (String)
        :asn_cidr: The assigned ASN CIDR (String)
        :asn_country_code: The assigned ASN country code (String)
        :entities: List of entity handles referred by the top level query.
        :network: Dictionary containing network information which consists
            of the fields listed in the ipwhois.rdap._RDAPNetwork dict.
        :objects: Dictionary of (entity handle: entity dict) which consists
            of the fields listed in the ipwhois.rdap._RDAPEntity dict.
        :raw: (Dictionary) - Whois results in json format if the inc_raw
            parameter is True.


    obj.lookup() returns
        :query: The IP address (String)
        :asn: The Autonomous System Number (String)
        :asn_date: The ASN Allocation date (String)
        :asn_registry: The assigned ASN registry (String)
        :asn_cidr: The assigned ASN CIDR (String)
        :asn_country_code: The assigned ASN country code (String)
        :nets: Dictionaries containing network information which consists
            of the fields listed in the ipwhois.whois.RIR_WHOIS dictionary.
            (List)
        :raw: Raw whois results if the inc_raw parameter is True. (String)
        :referral: Dictionary of referral whois information if get_referral
            is True and the server isn't blacklisted. Consists of fields
            listed in the ipwhois.whois.RWHOIS dictionary. Additional
            referral server informaion is added in the server and port
            keys. (Dictionary)
        :raw_referral: Raw referral whois results if the inc_raw parameter
            is True. (String)
    '''

    obj = IPWhois(ip, timeout=1)
    # ip_log_info = obj.lookup_rdap(depth=1)
    # ip_log_info2['network']['name']

    ip_log_info = obj.lookup()#get_referral=True) # for RWhois calls instead

    # isp_name = ip_log_info['nets'][0]['description']
    # print isp_name

    # le = ip_log_info['nets'][-1]  # last_entry
    # org_name = le['description']
    # print org_name

    # org_address = "{} {} {} {}".format(le['address'], le['city'], le['state'],
                                       # le['postal_code'], le['country'])
    # print org_name
    # print org_address
    # addresses.write(org_address.replace('\n', ' ') + '\n')

    nets_len = len(ip_log_info['nets'])
    descripts = [ip_log_info['nets'][i]['description'].replace('\n', ' ') + ' -----' for i in range(nets_len)]
    return {'organization': ip_log_info['nets'][-1]['description'].replace('\n', ' '),
            'descripts': descripts,
            'nets_len': nets_len,
            'asn': ip_log_info['asn']}



if __name__ == "__main__":
    # TODO make script except args for:
    # input: 'datasets/access.log'  (default)
    # output: stored under 'output/'
    #   json access_log_out.json    (default)
    #   csv access_log_out.csv
    # How to collect ip info???
    #   maxmind db - downloaded to filesystem under 'ipinfo/'
    #   rest api service - ipinfo.io    (creates db under 'ipinfo/')
    #   whois scraping - ipwhois python lib     (creates db under 'ipinfo/')
    # unit-tests
    # travis-ci

    data_in = path.abspath('datasets/access.log')
    data_out = path.abspath('datasets/access_log.out')


    ip_info = shelve.open('ip_info.shlv', writeback=True)
    asn_info = shelve.open('asn_info.shlv', writeback=True)

    with open(data_in, 'r') as input_data:
        for cnt, ln in enumerate(input_data):
            log = ln.strip()

            # OLD WAY
            # log = parse_log(log)
            # assert len(log) == 8

            # timestamp = convert_time_to_epoch(log['timestamp'])

            # assert len(log['request'].split(' ')) == 3
            # if (len(log['request'].split(' ')) > 3) or (len(log['request'].split(' ')) <= 1):
                # print log['request']
            # uri = log['request'].split(' ')[1]

            # referer = log['referer']
            # ip = log['host']


            # NEW WAY
            log = parse_log2(log)

            timestamp = log['time_received']
                # 'time_received': '[22/Oct/2014:06:15:14 -0700]',
                # 'time_received_datetimeobj': datetime.datetime(2014, 10, 22, 6, 15, 14),
                # 'time_received_isoformat': '2014-10-22T06:15:14',
                # 'time_received_tz_datetimeobj': datetime.datetime(2014, 10, 22, 6, 15, 14, tzinfo='0700'),
                # 'time_received_tz_isoformat': '2014-10-22T06:15:14-07:00',
                # 'time_received_utc_datetimeobj': datetime.datetime(2014, 10, 22, 13, 15, 14, tzinfo='0000'),
                # 'time_received_utc_isoformat': '2014-10-22T13:15:14+00:00'}

            # TODO time as epoch
            timestamp_epoch = timestamp

            uri = log['request_url']
            # if log['request_url'] != log['request_url_path']:
                # print log['request_url']        # the whole thing -- much longer  /svds.com/rockandroll/?utm_content=buffer3d4a8&utm_medium=social&utm_source=app.net&utm_campaign=buffer
                # print log['request_url_path']   # /svds.com/rockandroll/
                # print log['request_url_fragment']
                # print

            referer = log['request_header_referer']

            ########################
            ip = log['remote_host']
            # if ip not in ip_info:
                # try:
                    # ip_log_info = get_ip_info(ip)
                    # # ip_log_info2 = get_ip_info(ip)
                # except Exception as e:
                    # print "############################"
                    # print e     # TODO log this
                    # print "############################"
                    # ip_log_info = None
                # ip_info[ip] = ip_log_info
                # print_out = True
            # else:
                # ip_log_info = ip_info[ip]
                # print_out = False


            # if ip_log_info == None:     # just for debugging
                # ip_names.write('Failed to get ip_log_info\n')
                # continue    # nothing we can do if they didn't give back anything
            ########################



            ########################
            # asn = ip_log_info['asn']
            # if asn not in asn_info:
                # try:
                    # isp_name = use_asn_to_get_isp(ip)
                # except Exception as e:  # might be timeout here (maybe other things could happen)
                    # print "############################"
                    # # TODO log this
                    # print e
                    # print "############################"
                    # isp_name = None
                # asn_info[asn] = isp_name
                # # print_out = True
            # else:
                # isp_name = asn_info[asn]
                # # print_out = False

            if ip not in ip_info:
                try:
                    # asn, isp_name = use_ip_to_get_isp(ip)
                    ip_details = use_ip_to_get_isp(ip)
                except Exception as e:  # might be timeout here (maybe other things could happen)
                    print "############################"
                    print e     # TODO log this
                    print "############################"
                    ip_details = {'isp_name': None}

                ip_info[ip] = isp_name = ip_details['isp_name']
                print_out = True
            else:
                isp_name = ip_info[ip]#['isp_name']
                print_out = False
            ########################


            # log_this = '{} ------------ {}'.format(ip_log_info['descripts'], isp_name)
            # log_this = '{}'.format(ip_log_info['organization'])
            # log_this = '{}'.format(ip_log_info['descripts'])
            # if print_out:
                # if ip_log_info['nets_len'] >= 2:
                    # print cnt, ip_log_info['nets_len'], log_this
            # ip_names.write(log_this + '\n')

            log_this = '{}'.format(isp_name)
            if print_out:
                print cnt, log_this
            ip_names.write(log_this + '\n')

            lat, lon = get_lat_and_long(ip)


            # From ip address:
            # organization =
            # latitude =
            # longitude =
            # isp name =


            output = dict(
                date_and_time = timestamp_epoch,
                uri = uri,
                referer = referer,
                ip_address = ip,
                # organization = ip_log_info['organization'],
                latitude = lat,
                longitude = lon,
                isp_name = isp_name,
                )


    ip_names.close()
    # addresses.close()
    ip_info.close()
