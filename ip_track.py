
from flask import request
from flask import make_response

import threading

import logging

import requests

import functools
import datetime
import time

logging.getLogger("werkzeug").disabled = True

logging.basicConfig(filename='ip.log', encoding='utf-8', level=logging.DEBUG)

logger = logging.getLogger(__name__)

proxy_flags = {
    "use_proxy":False,
    "ip_address_header":"CF-Connecting-IP",
    "deny_proxy_fault":False,

    "allow_list":False,
    "allowed_ips":[],

    "use_webhook":False,
    "webhook_content":{
        "content":"Ip fault fromt %IP%, Ip header is %IP_HEADER%, subtype of error is %IP_ERROR% %REPEAT%"
    },
    "webhook_on":['ALLOWLIST_FAULT','PROXY_HEADER_NOT_FOUND'],

}

def convert_webhook_template(data,ip,ip_header,ip_error,path,repeat):
    new_data = {}
    if ip == None:
        ip = 'None'

    if ip_header == None:
        ip_header = 'None'
    
    for k,v in data.items():
        if type(v) == str:
            new_data[k.replace("%IP%",str(ip)).replace("%IP_HEADER%",ip_header).replace("%IP_ERROR%",ip_error).replace("%PATH%",path).replace("%REPEAT%",repeat)] = v.replace("%IP%",str(ip)).replace("%IP_HEADER%",ip_header).replace("%IP_ERROR%",ip_error).replace("%PATH%",path).replace("%REPEAT%",repeat)
        elif type(v) == dict:
            # yea yea ik repetition and such
            new_data[k.replace("%IP%",str(ip)).replace("%IP_HEADER%",ip_header).replace("%IP_ERROR%",ip_error).replace("%PATH%",path).replace("%REPEAT%",repeat)] = convert_webhook_template(v,ip,ip_header,ip_error,repeat)

    return new_data

def alert_webhook(ip,ip_header,ip_error,path):
    if ip_error not in proxy_flags['webhook_on']:
        return
    
    if proxy_flags['use_webhook']:
        wb_content = convert_webhook_template(proxy_flags['webhook_content'],ip,ip_header,ip_error,path,'')
        requests.post(proxy_flags['webhook_url'],json=wb_content)

def get_real_ip():
    if proxy_flags['allow_list'] and request.remote_addr not in proxy_flags['allowed_ips']:
        logger.error(f"IP fault, IP NOT IN ALLOWLIST, {request.remote_addr} => {request.method} {request.full_path}, header dump: {str(request.headers.__dict__)}")
        threading.Thread(target=alert_webhook,args=(request.remote_addr,request.headers.get(proxy_flags['ip_address_header']),'ALLOWLIST_FAULT',request.full_path)).start()
        return 0

    if not proxy_flags['use_proxy']:
        return request.remote_addr

    ip_header = request.headers.get(proxy_flags['ip_address_header'])

    if ip_header != None:
        return ip_header

    logger.error(f"IP fault the header is {ip_header}, {request.remote_addr} => {request.method} {request.full_path}, header dump: {str(request.headers.__dict__)}")
    threading.Thread(target=alert_webhook,args=(request.remote_addr,request.headers.get(proxy_flags['ip_address_header']),'PROXY_HEADER_NOT_FOUND',request.full_path)).start()

    if proxy_flags['deny_proxy_fault'] == True:
        return 0
    
    return request.remote_addr

def track_ip():
    def wrapper(func):
        @functools.wraps(func)
        def decorated(*args, **kwargs):
            response = make_response(func(*args, **kwargs))
            ip = get_real_ip()

            if ip == 0:
                return "<h1>Proxy fault</h1><p>If you are accesing the website without a proxy then cease imediatly, if you are a normal user refresh, this issue will solve itself.</p>",500
            logger.info(f"{ip} [{datetime.datetime.now()}] -> {request.method} {request.full_path} => {response.status_code}")
            return response
        
        return decorated
    return wrapper