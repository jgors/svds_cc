#!/usr/bin/env python

#----------------------------------------------------------------
# Author: Jason Gors <jasonDOTgorsATgmail>
# Creation Date: 03-16-2016
# Purpose:
#----------------------------------------------------------------
import datetime
from nose.tools import ok_

import data_processor

logs = ['''198.0.200.105 - - [14/Jan/2014:09:36:50 -0800] "GET /svds.com/rockandroll HTTP/1.1" 301 241 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36"''',
        '''98.27.164.183 - - [31/May/2014:09:05:18 -0700] "GET /svds.com/rockandroll/js/libs/ui/gumby.retina.js HTTP/1.1" 200 1912 "http://svds.com/rockandroll/" "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0"''',
        '''64.132.218.186 - - [22/Oct/2014:06:15:14 -0700] "GET /svds.com/rockandroll/fonts/icons/entypo.ttf HTTP/1.1" 404 4030 "http://svds.com/rockandroll/css/gumby.css" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.104 Safari/537.36"''']

items_of_interest = [{'remote_host': '198.0.200.105',
                      'request_header_referer': '-',
                      'request_url': '/svds.com/rockandroll',
                      'time_received_utc_isoformat': '2014-01-14T17:36:50+00:00'},
                     {'remote_host': '98.27.164.183',
                      'request_header_referer': 'http://svds.com/rockandroll/',
                      'request_url': '/svds.com/rockandroll/js/libs/ui/gumby.retina.js',
                      'time_received_utc_isoformat': '2014-05-31T16:05:18+00:00'},
                     {'remote_host': '64.132.218.186',
                      'request_header_referer': 'http://svds.com/rockandroll/css/gumby.css',
                      'request_url': '/svds.com/rockandroll/fonts/icons/entypo.ttf',
                      'time_received_utc_isoformat': '2014-10-22T13:15:14+00:00'}]

def test_parse_log():
    for i in range(3):
        log_parsed = data_processor.parse_log(logs[i])
        for k, v in items_of_interest[i].items():
            assert k in log_parsed
            assert v == log_parsed[k]



def test_get_lat_and_long():
    lat_and_lons = [(37.8858, -122.118), (41.2381, -81.8418), (40.8006, -73.9653)]
    for i in range(3):
        ok_(data_processor.get_lat_and_long(items_of_interest[i]['remote_host']) == lat_and_lons[i])


def test_split_list_into_chunks():
    ok_(list(data_processor.split_list_into_chunks(range(20), 10)) == [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                                                                       [10, 11, 12, 13, 14, 15, 16, 17, 18, 19]])
    ok_(list(data_processor.split_list_into_chunks(range(19), 3)) == [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9, 10, 11],
                                                                      [12, 13, 14], [15, 16, 17], [18]])
    ok_(list(data_processor.split_list_into_chunks(range(5), 13)) == [[0, 1, 2, 3, 4]])
