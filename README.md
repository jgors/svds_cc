[![Build Status](https://travis-ci.org/jgors/svds_cc.svg?branch=master)](https://travis-ci.org/jgors/svds_cc) travis-ci.org (master branch)

To execute, just run (only python2.7 compatabile):

```
python data_processor.py
```

By default, the script uses `./datasets/access.log` as the input file to process and writes the output to `./datasets/access_log.out`; however, the script can accept
two optional arguments:  `--infile` & `--outfile` for specifying alternative input and
output file paths to be used instead -- like so:

```
python data_processor.py --infile /alternative/input/filepath --outfile ~/diff/output/filepath
```

**Note**, there are also required dependencies that can be installed via:

```
pip install -r requirements.txt --user --upgrade
```

Additionally, unit-tests can be run from the root of the repo via:

```
nosetests -s -v
```


I could not figure out how to get the `organization` field in any consistent and usable way, so put the isp as the organization (which is commonly the case I noticed).  Regarding this, I made several attempts at scraping whois data per each ip address to get this field, which was promising, albeit a bit too unstructured to be reliable; also, doing so took way too long to be usable at any reasonable scale.  I did find numerous companies offering the "organization" data, but under the time constraints I couldn't implement a free solution.  As for two great paid options:

This seems perfect, but costs $:
http://ip-api.com/docs/api:json

Likewise, Maxmind has an "IP database" [1] that claims to, "Determine the Internet Service Provider, Registering Organization, and AS Number associated with an IP address"; though again, this costs $.  Along this point, the `latitude` and `longitude` I got were attained using Maxmind's free location database [2], which they say is less accurate than the paid version.  I had hoped to gather the location data via some sort of api (e.g. something like google maps api), but could not get to it.

Lastly, I also wanted to refractor and implement an SQL(ite) backend, which would likely make the code scale better and be more fault tolerant, but again, those time constraints.

[1] https://www.maxmind.com/en/geoip2-isp-database

[2] https://www.maxmind.com/en/open-source-data-and-api-for-ip-geolocation
