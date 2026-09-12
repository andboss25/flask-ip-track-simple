
from flask import Flask
from flask import request

import ip_track


ip_track.proxy_flags = {
    "use_proxy":False,
    "ip_address_header":"CF-Connecting-IP",
    "deny_proxy_fault":False,

    "allow_list":False,
    "allowed_ips":[],

    "use_webhook":False,
    "webhook_content":{
        "content":"Ip fault from %IP%, Ip header is %IP_HEADER%, subtype of error is %IP_ERROR%"
    },
    "webhook_on":['PROXY_HEADER_NOT_FOUND'],
    "webhook_url":"",

    "crypt_ips":True
}

app = Flask(__name__)

@app.route('/')
@ip_track.track_ip()
def index():
    return 'yooo',200

app.run('127.0.0.1',80, debug= True)