import boto3
import sys
import urllib
from urllib.request import urlopen

# region Variables
#This is github demo
#This is github demo 2
#This is github demo 3
#This is github demo branch 1
ACCESS_KEY = 'Your Access Key'
SECRET_KEY = 'Your Secret Key'
IPSetId = 'ID of the IPList that you want to push the IP List'
file_url = 'https://myip.ms/files/blacklist/csf/latest_blacklist.txt'
ChangeToken = ''
DataFromWAF = set()
DataFromMyIP = set()
DataFromLocalFile = set()
DataDiff = set()
DictIPs = {}
arrIP_KVP = []
wafRegionalClient = boto3.client('waf-regional',
                                 aws_access_key_id=ACCESS_KEY,
                                 aws_secret_access_key=SECRET_KEY,
                                 region_name='region ex : us-west-2')
# endregion


def _FetchDataFrommyipms():
    retval = set()
    txt = urllib.request.urlopen(file_url)

    for line in txt:
        line = line.decode('utf-8')
        # line = line.remove('')
        if "#" in str(line):
            continue
        else:
            if ":" in str(line):
                line = str(line).rstrip("\n\r") + '/128'
            else:
                line = str(line).rstrip("\n\r") + '/32'
            # # log.debug(line)
        retval.add(line)

    return retval


def _FetchDataFromWAFIPlist():
    retval = set([])
    IPSetData = wafRegionalClient.get_ip_set(IPSetId=IPSetId)
    print(IPSetData)
    IPSetData = IPSetData['IPSet']['IPSetDescriptors']
    for row in range(len(IPSetData)):
        retval.add(IPSetData[row]['Value'])
    return retval

# region Main


def _getChangeToken():
    response = wafRegionalClient.get_change_token()
    return response['ChangeToken']


def _pushToWAF():
    global DataFromMyIP
    global DataFromWAF
    global DictIPs
    global DataDiff

    for values in set(DataDiff):
        try:
                if len(str(values)) > 3:# Random number for removing blank lines.

                    update_sets = []
                    if ":" in str(values):
                        DictIPs['Type'] = 'IPV6'
                    else:
                        DictIPs['Type'] = 'IPV4'

                    DictIPs['Value'] = values
                    t = {
                        'Action': 'INSERT',
                        'IPSetDescriptor': DictIPs
                    }
                    update_sets.append(t)
                    print(update_sets)
                    response = wafRegionalClient.update_ip_set(
                        IPSetId=IPSetId,
                        ChangeToken=_getChangeToken(),
                        Updates=update_sets)
                    print(response)
        except Exception as e:
            print("Unable to update WAF IP List. Error --> " + str(values))


def main():
    global DataFromMyIP
    global DataFromWAF
    global DataDiff

    try:
        DataFromMyIP = _FetchDataFrommyipms()
        print('myip.ms Data fetched')
    except Exception as e:
        print("Unable to fetch IP List file. Error --> " + e)
        sys.exit(1)

    try:
        DataFromWAF = _FetchDataFromWAFIPlist()
        print('WAF Data fetched')
    except Exception as e:
        print("Unable to fetch WAF IP List. Error --> " + e)
        sys.exit(1)

    DataDiff = DataFromMyIP - DataFromWAF

    print("New IPs Count :" + str(len(DataDiff)))
    if len(DataDiff) > 0:
        _pushToWAF()
    else:
        print('Nothing to update.')

# endregion


if __name__ == '__main__':
    main()
