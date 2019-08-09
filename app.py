from flask import Flask, request, render_template,session
import requests
import json
from bs4 import BeautifulSoup
import time
import os



app = Flask(__name__)
app.secret_key = os.urandom(64)

def vtscan_result(filehash):
    
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': session["apikey"], 'resource': filehash, 'allinfo': True}
    response = requests.get(url, params=params)
    if response.status_code != 200:
        print(response.status_code)
        return {'errorcode' : response.status_code}
    return response.json()

def getavdetect(filechecksum,respjson,avscanner):
    filestatus = {}
    print(respjson)
    if 'scans' not in respjson:
        filestatus.update({filechecksum:'FILENOTFOUND'})
    elif avscanner not in respjson['scans']:
        temp = ['NOTSCANNEDWITH_'+avscanner, respjson['scan_date'],respjson['total'],respjson['positives']]
        filestatus.update({filechecksum:temp})
    elif respjson['scans'][avscanner]['detected'] == True:
        temp = [respjson['scans'][avscanner]['result'], respjson['scan_date'],respjson['total'],respjson['positives']]
        filestatus.update({filechecksum:temp})
    else:
        temp = ['FILENOTDETECTED',respjson['scan_date'],respjson['total'],respjson['positives']]
        filestatus.update({filechecksum:temp})
    return filestatus

def splitlistbystep(lst,step):
    slist = []
    for i in range(0, len(lst), step):
        slist.append(lst[i:i + step])
    return slist

def checkvt(hashlist):
    time.sleep(20)
    strhashfile = ",".join(hashlist)
    resp_json = vtscan_result(strhashfile)
    return resp_json



@app.route('/', methods=['GET','POST'])
def index():
    if 'apikey' in session:
        return render_template('vtcheck.html')
    return render_template('home.html')

@app.route('/vtcheck',methods=['POST'])
def get_vtkey():
    
    if 'apikey' not in session:
        session['apikey'] = request.form['APIKEY']
    
    return render_template('vtcheck.html')


@app.route('/submit',methods=['POST'])
def submit():
    hashlist = request.form["text"]
    avscanner = request.args.get("avscanner")
    #print(avscanner)
    #hashlist = hashlist.split(" ")
    #hashlist = [x.strip('\\r\\n') for x in hashlist]
    filestocheck = []
    for line in hashlist.splitlines():
        filestocheck.append(line)

    #print(filestocheck)
    splitlist = splitlistbystep(filestocheck,4)
    filestatus = {}
    for flist in splitlist:
        respjson = checkvt(flist)
        if len(flist) != 1:
            for flchcksum,scan in zip(flist,respjson):
                filestatus.update(getavdetect(flchcksum,scan,avscanner))
        else:
            filestatus.update(getavdetect(flist[0],respjson,avscanner))

    print(filestatus)
    return render_template('table.html', result=filestatus)

if __name__ == '__main__':
    app.run()