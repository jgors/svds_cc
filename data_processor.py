#!/usr/bin/env python

#----------------------------------------------------------------
# Author: Jason Gors <jasonDOTgorsATgmail>
# Creation Date: 03-14-2016
# Purpose:
#----------------------------------------------------------------

import os
from os import path
from os.path import join as opj
import re
import shelve
import time
import json
from time import strptime
from calendar import timegm
import logging
import argparse

from ipwhois import IPWhois
from apache_log_parser import make_parser
from cymruwhois import Client
from geoip import geolite2


data_dir = 'datasets'
data_out_intermediate = path.abspath(opj(data_dir, 'access_log_intermediate.out'))
logging.basicConfig(filename='logging.log', filemode='w', level=logging.DEBUG)


def time_logger(func):
    ''' Simple decorator to help with logging func calls and timestamping '''
    def wrap(*args, **kwargs):
        t0 = time.time()
        result = func(*args, **kwargs)
        logging.info('{}: {}'.format(func.__name__, time.time() - t0))
        return result
    return wrap


def parse_log_regex(log):
    ''' Parses a single server log

        log: a line from the server log file
        Returns: parsed log

        NOTE: abandoned this b/c:
        log files may contain information supplied directly by the client, without escaping. Therefore,
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
        #  pull out the uri from the request:   r'.+GET (?P<url>\/(?P<method>.+?)\?.+).+HTTP\/1\.1" (?P<statuscode>\d{3})'

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
    # if res["username"] == "-":
        # res["username"] = None
    # if res["size"] == "-":
        # res["size"] = '0'
    return res


def parse_log(log):
    ''' Parses a single server log.

        log: a line from the server log file
        Returns: parsed log
    '''
    apache_combined_format = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
    line_parser = make_parser(apache_combined_format)
    log_data = line_parser(log)
    return log_data


def get_isp(ip):
    ''' Gets the isp name for the ip
        Much faster than the ipwhois lookup, but there is no "organization" field.

        ip: an ip address parsed out of the log file.
        Returns: dict containing isp name for the ip
    '''
    c = Client()    # should probably pull this out of here so not to create it each time
    r = c.lookup(ip)
    return {'isp_name': r.owner}


# def get_lat_and_long(location):
    # ''' could use api (google maps?) to get lat & lon by using
    #     the address pulled out from the whois scraping
    # '''


def get_lat_and_long(ip):
    ''' Gets the latitude and longitude for the ip address

        ip: an ip address parsed out of the log file.
        Returns: a tuple of (lat, lon) or (None, None) if not found
        NOTE: uses the maxmind free database underneath, so location data
              might be somewhat suboptimal.
    '''
    # maybe timezone could be useful for converting the time to the epoch
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


def get_ip_info(ip):
    ''' Gets the whois info for the ip address

        ip: an ip address parsed out of the log file.
        Returns: dict of information relating to the ip address
        NOTE: abandoned this because it was way too slow and the
              results are very unstructured.
    '''

    obj = IPWhois(ip, timeout=1)
    ip_log_info = obj.lookup()#get_referral=True) # for RWhois calls instead
    le = ip_log_info['nets'][-1]  # last_entry ...more likely to the the organization?
    org_address = "{} {} {} {}".format(le['address'], le['city'], le['state'],
                                       le['postal_code'], le['country'])
    return {'organization': le['description'].replace('\n', ' '),
            'address': org_address}


def split_list_into_chunks(l, sublist_size):
    ''' Yields successive sublist_size'd chunks from l

        l: list to divide into chunks
        sublist_size: the size of the chunks to divide the list into
        Returns: a generator that when called, gives back lists of
                 size sublist_size
    '''
    n = max(1, sublist_size)
    return (l[i:i + n] for i in xrange(0, len(l), n))


@time_logger
def restructure_logs(data_in_fpath, data_out_fpath=data_out_intermediate):
    ''' Make a first pass through the data to clean it and then
        save back to file to be used later for adding in the ip info.

        data_in_fpath: path to the server log file
        Returns: a set of the unique_ips seen
    '''
    unique_ips = set()  # NOTE this might get too big and blow up
    with open(data_in_fpath, 'r') as input_data:
        with open(data_out_fpath, 'w') as out_data:
            for cnt, ln in enumerate(input_data):
                # if cnt > 2000:
                    # break

                log = parse_log(ln.strip())
                ip = log['remote_host']

                output = dict(
                    date_and_time=timegm(strptime(log['time_received_utc_isoformat'], "%Y-%m-%dT%H:%M:%S+00:00")),
                    uri=log['request_url'],
                    referer=log['request_header_referer'],
                    ip_address=ip,
                    # From ip address
                    # organization=ip_log_info['organization'],
                    # latitude=lat, longitude=lon, isp_name=isp_name,
                    )

                json.dump(output, out_data)
                out_data.write('\n')
                unique_ips.add(ip)
    return unique_ips


@time_logger
def build_ip_db(unique_ips):
    ''' Builds up a db of ip addresses that were in the server logs.

        unique_ips: set of ip's that were seen in the server logs
        Returns: the ip db with 'isp_name', 'latitude and 'longitude'
    '''
    c = Client()
    ip_db = shelve.open(opj(data_dir, 'ip.db'))     # NOTE again, this might get too big and blow everything up
    unique_ips = [ip for ip in unique_ips if ip not in ip_db]     # if we have stuff in ip.db already from a previous run
    ips_fetching = 'Fetching info for this many IPs: {}'.format(len(unique_ips))
    print ips_fetching
    logging.info(ips_fetching)
    for subset_of_unique_ips in split_list_into_chunks(unique_ips, 10000): # only do 10,000 ip's at a time
        for ip_addr, ip_info_dict in c.lookupmany_dict(subset_of_unique_ips).iteritems():
            lat, lon = get_lat_and_long(ip_addr)    # NOTE maybe take this out so the shelve doesn't ballon too big
            ip_db[ip_addr] = {'isp_name': ip_info_dict.owner,
                              # 'organization': ??? -- would probably need to pull out from whois, but slow and messy
                              'latitude': lat,
                              'longitude': lon}
    return ip_db


@time_logger
def update_log_dataset(data_out, data_in=data_out_intermediate):
    ''' Adds in the ip db info to the log output file

        data_out:   path for where to save the output data.
        Returns: None
    '''
    with open(data_in, 'r') as logs_reformatted:
        with open(data_out, 'w') as final_output:
            for json_dict in logs_reformatted:
                log = json.loads(json_dict)
                ip_addr = str(log['ip_address'])
                log['isp_name'] = ip_db[ip_addr]['isp_name']
                log['organization'] = ip_db[ip_addr]['isp_name']
                log['lat'] = ip_db[ip_addr]['latitude']
                log['lon'] = ip_db[ip_addr]['longitude']
                json.dump(log, final_output)
                final_output.write('\n')
    os.remove(data_in)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process server logs.')
    data_in = path.abspath(opj(data_dir, 'access.log'))
    data_out = path.abspath(opj(data_dir, 'access_log.out'))
    parser.add_argument('--infile', default=data_in,
                    nargs='?', const=data_in,
                    help='path for input file to process.')

    parser.add_argument('--outfile', default=data_out,
                    nargs='?', const=data_out,
                    help='path where to save the processed logs.')

    args = parser.parse_args()
    data_in = args.infile
    if not os.path.isfile(data_in):
        raise SystemExit, "ERROR: {} is not a file on the filesystem".format(data_in)
    data_out = args.outfile

    # How to collect "organization" info?
    #   1. maxmind db - paid db you download to filesystem
    #   2. api - http://ip-api.com/docs/api:json - perfect, but requires $
    #   3. whois scraping - ipwhois python lib - slow and too unstructured to make sense be useful

    # Clean up the log file and figure out what ip's have visited the site
    unique_ips = restructure_logs(data_in)

    # Build up a db containing the ip specific info for each unique ip that was seen
    ip_db = build_ip_db(unique_ips)

    # Add the new ip derived info back into the original log dataset
    update_log_dataset(data_out)
    print "Finished.  See results in {}".format(data_out)
    ip_db.close()
