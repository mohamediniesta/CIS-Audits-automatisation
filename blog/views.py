# -*- coding: utf-8 -*-
from __future__ import unicode_literals,division
from django.http import HttpResponse,HttpResponseRedirect
from django.shortcuts import render
import subprocess
import re
from pexpect import pxssh
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
cptd = 0
cptm = 0
context = {}
def count_cpt(var):
    global cptm
    global cptd
    if var != "":
        cptm = cptm +1
    else:
        cptd = cptd +1
def count_cpt_inv(var):
    global cptm
    global cptd
    if var != "":
        cptm = cptm +1
        cptd = cptd +1
def saute(str):
    return '\r\n'.join(str.splitlines()[1:])
def saute3(str):
    s = ""
    for line in str.splitlines()[2:]:
        line = line.replace('<','&lt')
        line = line.replace('>','&gt')
        s+=line+"<br>"
    return s
def home(request):
    global cptd
    global cptm
    cptd = 0
    cptm = 0
    host = request.session.get('host')
    if host is None:
        return HttpResponseRedirect("/")
    page = request.GET.get("page")
    if (page is None) or (page not in {'modules','permissions','options','ssl','access','dos','armor','se','info','log','request'}):
        return HttpResponseRedirect("/scan/?page=modules")
    auth = request.session.get('auth')
    ldap = request.session.get('ldap')
    log = request.session.get('log')
    dav = request.session.get('dav')
    status = request.session.get('status')    
    index = request.session.get('index')
    proxy = request.session.get('proxy')
    user = request.session.get('user')
    info = request.session.get('info')
    count_cpt(auth)
    count_cpt_inv(ldap)
    count_cpt(log)
    count_cpt_inv(dav)
    count_cpt_inv(status)
    count_cpt_inv(index)
    count_cpt_inv(proxy)
    count_cpt_inv(user)
    count_cpt_inv(info)
    pourcentage_danger = int((cptd / 9) * 100)
    group_own = request.session.get('groupo')
    user_own = request.session.get('usero')
    passwd = request.session.get('passwd')
    system = request.session.get('system')
    id = request.session.get('id')
    dates = request.session.get('date')
    pas = request.session.get('passwd')
    CDD = request.session.get('CDD')
    LokF = request.session.get('LokF')
    FilePID = request.session.get('FilePID')
    accessLog = request.session.get('accessLog')
    lock = request.session.get('lock')
    ListenDir = request.session.get('ListenDir')
    WriteADF = request.session.get('WriteADF')
    WriteARDF = request.session.get('WriteARDF')
    apacheDir = request.session.get('apacheDir')
    apacheGrp = request.session.get('apacheGrp')
    WrA = request.session.get('WrA')
    BrowserFraOpt = request.session.get('BrowserFraOpt')
    HttpTraceM = request.session.get('HttpTraceM')
    DHtmlContent = request.session.get('DHtmlContent')
    DCGIContentP = request.session.get("DCGIContentP")
    OvAll = request.session.get('OvAll')
    OsAcc = request.session.get('OsAcc')
    HttpRM = request.session.get('HttpRM')
    DCGIContentTest = request.session.get("DCGIContentTest")
    WebC = request.session.get('WebC')
    print WebC
    cptd = 0
    if "Require all denied" not in OsAcc:
        cptd = cptd +1
    if "AllowOverride none" not in OsAcc:
        cptd = cptd +1
    if "Require" not in WebC:
        cptd = cptd +1
    pourcentage_access = int((cptd / 4) * 100)
    cptd = 0
    if user_own[5:]=="root":
        cptd = cptd +1
    if "/sbin/nologin" not in passwd:
        cptd = cptd +1
    if lock != "Mot de passe verrouillé.":
        cptd = cptd +1
    if apacheDir != "":
        cptd = cptd +1
    if apacheGrp != "":
        cptd = cptd +1
    if WrA != "":
        cptd = cptd +1
    if WriteADF != "":
        cptd = cptd +1
    if WriteARDF != "":
        cptd = cptd +1
    HttpPrVer = request.session.get('HttpPrVer')
    DenyIP = request.session.get('DenyIP')
    pourcentage_perm = int((cptd / 12) * 100)
    ServTok = request.session.get("ServTok")
    ServerS = request.session.get("ServerS")
    Etag = request.session.get("Etag")
    FileE = request.session.get('FileE')
    OsRootD = request.session.get('OsRootD')
    icons = request.session.get("Icons")
    WebRootD = request.session.get('WebRootD')
    OtherD = request.session.get('OtherD')
    cptd = 0
    if "Prod" not in ServTok and "ProductOnly" not in ServTok:
        cptd = cptd +1
        print 1
    if "ServerSignature Off" not in ServerS:
        cptd = cptd +1
        print 2
    if "inode" in Etag or "+inode" in Etag or "all" in Etag:
        cptd = cptd +1
        print 3
    if icons != "":
        cptd = cptd +1
        print 4
    pourcentage_info = int((cptd / 4) * 100) 
    LimitLine = (request.session.get("LimitLine"))[16:]
    LimitField = (request.session.get("LimitField"))[18:]
    LimitFieldS = (request.session.get("LimitFieldS"))[21:]
    LimitBody = (request.session.get("LimitBody"))[16:]
    if LimitLine == "":
        LimitLine = 0
    else:
        LimitLine = int(LimitLine)
    if LimitField == "":
        LimitField = 0
    else:
        LimitField = int(LimitField)
    if LimitFieldS == "":
        LimitFieldS = 0
    else:
        LimitFieldS = int(LimitFieldS)
    if LimitBody == "":
        LimitBody = 0
    else:
        LimitBody = int(LimitBody)
    cptd = 0
    if LimitLine == 0 or LimitLine > 512:
        cptd = cptd +1
    if LimitField > 100 or LimitField != 0:
        cptd = cptd +1
    if LimitFieldS == 0 or LimitFieldS > 1024:
        cptd = cptd +1
    if LimitBody == 0 or LimitBody > 102400:
        cptd = cptd +1
    pourcentage_limit = int(( cptd /4 ) *  100)
    TimeOut = (request.session.get("TimeOut"))
    KeepAlive = request.session.get("KeepAlive")
    MaxKeep = request.session.get("MaxKeep")
    KeepTime = request.session.get("KeepTime")
    print TimeOut
    if TimeOut == "":
        TimeOut = 0
    else:
        TimeOut = int(TimeOut[7:])
    if MaxKeep == "":
        MaxKeep = 0
    else:
        MaxKeep = int(MaxKeep[20:])
    if KeepTime == "":
        KeepTime = 0
    else:
        KeepTime = int(KeepTime[16:])
    cptd = 0
    if TimeOut == 0 or TimeOut > 10:
        cptd = cptd +1
    if MaxKeep == 0 or MaxKeep < 100:
        cptd = cptd +1
    if "KeepAlive On" not in KeepAlive and KeepAlive != "":
        cptd = cptd +1
    if KeepTime != 0 and KeepTime > 15:
        cptd = cptd +1
    pourcentage_dos = int((cptd / 4 ) * 100)
    context = {
    'auth':auth,
    'ldap':ldap,
    'log':log,
    'dav':dav,
    'DCGIContentTest':DCGIContentTest,
    'status':status,
    'index':index,
    'proxy':proxy,
    'user':user,
    'info':info,
    'grp_apache':group_own,
    'usr_apache':user_own,
    'shell_apache':passwd,
    'system':system,
    'id':id,
    'dates':dates,
    'page':page,
    'pourcentage_d':pourcentage_danger,
    'nb_mod':cptm,
    'passwd':pas,
    'OtherD':OtherD,
    'apacheDir':apacheDir,
    'DCGIContentP':DCGIContentP,
    'apacheGrp':apacheGrp,
    'CDD':CDD,
    'HttpTraceM':HttpTraceM,
    'LokF':LokF,
    'DenyIP':DenyIP,
    'FilePID':FilePID,
    'accessLog':accessLog,
    'WriteADF':WriteADF,
    'WriteARDF':WriteARDF,
    'lock':lock,
    'WrA':WrA,
    'HttpPrVer':HttpPrVer,
    'FileE':FileE,
    'OvAll':OvAll,
    'OsAcc':OsAcc,
    'pourcentage_access':pourcentage_access,
    'WebC':WebC,
    'ListenDir':ListenDir,
    'BrowserFraOpt':BrowserFraOpt,
    'pourcentage_p':pourcentage_perm,
    'HttpRM':HttpRM,
    'ServTok':ServTok,
    'ServerS':ServerS,
    'Etag':Etag,
    'DHtmlContent':DHtmlContent,
    'Icons':icons,
    'pourcentage_i':pourcentage_info,
    'OsRootD':OsRootD,
    'WebRootD':WebRootD, 
    'LimitLine':LimitLine,
    'LimitField':LimitField,
    'LimitFieldS':LimitFieldS,
    'LimitBody':LimitBody,
    'pourcentage_limit':pourcentage_limit,
    'TimeOut':TimeOut,
    'KeepAlive':KeepAlive,
    'MaxKeep':MaxKeep,
    'KeepTime':KeepTime,
    'pourcentage_dos':pourcentage_dos,
     }
    #context = request.session.get('context')
    return render(request,"/root/Bureau/apache/blog/templates/test.html",context)
def cmdd(ss,cmd,res,request):
    ss.sendline(cmd)
    ss.prompt()
    if res in {"OsAcc","WebC","OvAll","OtherD","OsRootD","WebRootD","ListenDir"}:
        request.session[res] = saute3(ss.before)
    else:
        request.session[res] = saute(ss.before)
def login(request):
    old = request.session['old'] = request.POST
    user =  request.POST.get("user")
    password = request.POST.get("pass")
    host = request.POST.get("host")
    global context
    if request.method == "POST":
        try:
            request.session['host'] = host
            s = pxssh.pxssh()
            s.login(host,user,password)
            """s.sendline("sudo su")
            s.sendline(password)
            s.prompt()
	    s.sendline('id')
	    s.prompt()
	    print s.before"""
	    cmdd(s,'httpd -M | egrep "auth._" --color=none','auth',request)
	    cmdd(s,'httpd -M | egrep "ldap" --color=none','ldap',request)		
            cmdd(s,'httpd -M | grep log_config --color=none','log',request)
            cmdd(s,'httpd -M | grep "dav_" --color=none','dav',request)
            cmdd(s,'httpd -M | egrep "status_module" --color=none','status',request)
            cmdd(s,'httpd -M | grep autoindex_module --color=none','index',request)
            cmdd(s,'httpd -M | egrep "proxy_" --color=none','proxy',request)
            cmdd(s,'httpd -M | grep userdir --color=none','user',request)
            cmdd(s,'httpd -M | egrep "info_module" --color=none','info',request)
            request.session['prc'] = int((cptd / 9) * 100)
            cmdd(s,"grep -i '^User' /etc/httpd/conf/httpd.conf --color=none",'usero',request)      
	    own=request.session['usero'][5:]
            cmdd(s,'grep -i "^Group" /etc/httpd/conf/httpd.conf --color=none','groupo',request)
            cmdd(s,"grep {0} /etc/passwd --color=none".format(own),'passwd',request)
            cmdd(s,"find /etc/httpd/ \! -user root -ls",'apacheDir',request)
            cmdd(s,'find /etc/httpd/ \! -group root -ls','apacheGrp',request)
	    cmdd(s,'find -L /etc/httpd \! -type l -perm /o=w -ls ','WrA',request)
            cmdd(s,'httpd -V','LokF',request)
            cmdd(s,'grep -i -A 12 "<Directory[[:space:]]" /etc/httpd/conf/httpd.conf --color=none','OtherD',request)
            cmdd(s,'cat /run/httpd/httpd.pid','FilePID',request)
            cmdd(s,'cat /var/log/httpd/access_log','accessLog',request)
	    cmdd(s,'ls -al /var/log/httpd --color=none','CDD',request)
            cmdd(s,'find -L /etc/httpd/ \! -type l -perm /g=w -ls','WriteADF',request)
            cmdd(s,'find -L /root/ -group root -perm /g=w -ls','WriteARDF',request)
            cmdd(s,'grep -i AllowOverride /etc/httpd//conf/httpd.conf --color=none','OvAll',request) 
            cmdd(s,"perl -ne 'print if /^ *<Directory *\//i .. /<\/Directory/i' /etc/httpd/conf/httpd.conf",'OsAcc',request)
            cmdd(s,"perl -ne 'print if /^ *<Directory */i .. //<\/Directory/i' /etc/httpd/conf/httpd.conf",'WebC',request)
            cmdd(s,"grep -i ServerToken /etc/httpd/conf/httpd.conf --color=none","ServTok",request)
            cmdd(s,"grep -i ServerSignature /etc/httpd/conf/httpd.conf --color=none","ServerS",request)
            cmdd(s,"grep -i FileETag /etc/httpd/conf/httpd.conf --color=none","Etag",request)
            cmdd(s,'ls -al /var/www/cgi-bin/ | grep printenv --color=none','DCGIContentP',request)
            cmdd(s,' ls -al /var/www/cgi-bin/ | grep test-cgi  --color=none','DCGIContentTest',request)
            cmdd(s,"grep -i icons /etc/httpd/conf/httpd.conf --color=none","Icons",request)
            cmdd(s,"ls /etc/httpd/conf.d/ | grep welcome.conf --color=none",'DHtmlContent',request)
            cmdd(s,"perl -ne 'print if /^ *<Directory *\//i .. /<\/Directory/i' /etc/httpd/conf/httpd.conf",'OsRootD',request)
            
            cmdd(s,' cat /etc/httpd/conf/httpd.conf | grep RewriteC  --color=none','DenyIP',request)
            cmdd(s,'cat /etc/httpd/conf/httpd.conf | grep Rewrite  --color=none','HttpPrVer',request)
            cmdd(s,'grep -i X-Frame-Options /etc/httpd/conf/httpd.conf --color=none','BrowserFraOpt',request)
            cmdd(s,"cat /etc/httpd/conf/httpd.conf  | grep Listen --color=none",'ListenDir',request)
            cmdd(s,"find /var/www/html/ -type f -name '*.*' | awk -F. '{print $NF }' ",'FileE',request)
            cmdd(s,'cat /etc/httpd/conf/httpd.conf | grep TraceEnable --color=none','HttpTraceM',request)
            cmdd(s,'cat /etc/httpd/conf.d/userdir.conf | grep Require --color=none ','HttpRM',request)
            cmdd(s,'perl -ne "print if /^ *<Directory */i .. /<\/Directory/i" /etc/httpd/conf/httpd.conf','WebRootD',request)
            cmdd(s,'grep LimitRequestLine /etc/httpd/conf/httpd.conf --color=none','LimitLine',request)
            cmdd(s,'grep LimitRequestFields /etc/httpd/conf/httpd.conf --color=none','LimitField',request)
            cmdd(s,'grep LimitRequestFieldSize /etc/httpd/conf/httpd.conf --color=none','LimitFieldS',request)
            cmdd(s,'grep LimitRequestBody /etc/httpd/conf/httpd.conf --color=none','LimitBody',request)
            cmdd(s,'grep TimeOut /etc/httpd/conf/httpd.conf --color=none','TimeOut',request)
            cmdd(s,'grep KeepAlive /etc/httpd/conf/httpd.conf --color=none','KeepAlive',request)
            cmdd(s,'grep MaxKeepAliveRequests /etc/httpd/conf/httpd.conf --color=none','MaxKeep',request)
            cmdd(s,'grep KeepAliveTimeout /etc/httpd/conf/httpd.conf --color=none',"KeepTime",request)
            s.sendline("passwd -S {0}".format(own))
            s.prompt()
            request.session['lock'] = saute(s.before)[saute(s.before).index('(')+1:saute(s.before).index(')')]
            #print "lock = ",request.session['lock']
            cmdd(s,'uname -a','system',request)
            s.sendline("id")
            s.prompt()
            request.session['id'] = saute(s.before[1:(s.before.index('context'))-1])
            s.sendline("date")
            s.prompt()
            request.session['date'] = s.before
            s.logout()
        except pxssh.ExceptionPxssh as e:
            print "Erreur SSH ! "
        return HttpResponseRedirect("/scan/?page=modules")
    return render(request,"/root/Bureau/apache/blog/templates/login.html",context)
