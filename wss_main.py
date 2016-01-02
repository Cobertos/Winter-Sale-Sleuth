#Steam Winter Sale Sleuth for the 2015/2016 sale
#Author: Coburn

#This logs you into steam and queries every appId for passwords in a given array below
#See Readme.md for more info

#USAGE: python wss_main.py

import re
import json
import time
import os
import sys
import webbrowser
from http.cookiejar import LWPCookieJar

#3rd party
import Crypto
import requests

#GLOBAL CONFIGURATION STUFF
logFile = "./log.txt"               #Where to save your logs
cookieFile = "./loginCookies.txt"   #Where to save your cookies
passwords = [                       #The passwords to search
    "8336041748881"
]
requestDelay = 0.033                #Delay between requests in seconds

#END GLOBAL CONFIGURATION STUFF
user_agent = "Steam Winter Sale 2015_16 Python Crawler"

#Setting up a quick logging function
logFile = os.path.abspath(logFile)
cookieFile = os.path.abspath(cookieFile)

def hasnext(itr):
    itr = iter(itr)
    try:
        next(itr)
    except StopIteration:
        return False
    else:
        return True

logFile = open(logFile, 'a')

def logPrint(myStr):
    global logFile
    print(myStr)
    logFile.write(myStr)

#LOGIN (Thanks to https://gist.github.com/maxisoft/8364262 for original script)
def loginSteam(usr, pwd, emailAuth="", captcha="", captchaGID="", twoFactorAuth="", session=None):
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
    import base64
    global user_agent

    reqObj = requests
    if session != None:
        reqObj = session
    
    # Request key
    url = "https://steamcommunity.com/login/getrsakey/"
    values = {"username" : usr, "donotcache" : str(int(time.time()*1000))}
    headers = { "User-Agent" : user_agent }
    data = reqObj.request("POST", url, data=values, headers=headers).json()
    

    # Encode key
    mod = int(str(data["publickey_mod"]), 16)
    exp = int(str(data["publickey_exp"]), 16)
    rsa = RSA.construct((mod, exp))
    cipher = PKCS1_v1_5.new(rsa)
    pwdEnc = base64.b64encode(cipher.encrypt(pwd.encode("ascii")))

    # Login
    url = "https://steamcommunity.com/login/dologin/"
    values = {
            "username" : usr,
            "password": pwdEnc,
            "emailauth": emailAuth,
            "loginfriendlyname": "Winter Sale Python Crawler",
            "captchagid": captchaGID,
            "captcha_text": captcha,
            "emailsteamid": "",
            "rsatimestamp": data["timestamp"],
            "remember_login": False,
            "donotcache": str(int(time.time()*1000)),
    }
    headers = { "User-Agent" : user_agent }
    resp = reqObj.request("POST", url, data=values, headers=headers)

    return resp

def hitSteamStore(pwd, appId, reqSession):
    global user_agent
        
    url = "http://store.steampowered.com/actions/clues"
    values = { "key" : pwd }
    headers = {
        "Referer":"http://store.steampowered.com/app/"+appId+"/", #Referrer AppID we're looking at
        "User-Agent" : user_agent
    }
    resp = reqSession.request("POST", url, data=values, headers=headers)
    
    return resp

def getNewSteamSession():
    global cookieFile

    reqSession = None
    
    #Check if the old one exists and
    #Only use if new enough (4 hours was an arbitrary choice)
    if os.path.isfile(cookieFile) and time.time() < float(os.path.getmtime(cookieFile)) + (60*60*4):
        reqSession = requests.Session()
        reqSession.cookies = LWPCookieJar(cookieFile)
        reqSession.cookies.load()
        if hasnext(reqSession.cookies) == False: #No cookies
            reqSession = None
    
    #Otherwise, if the cookies don't load or the file is too old
    if reqSession == None:
        reqSession = requests.Session()
        reqSession.cookies = LWPCookieJar(cookieFile)
        respLogin = None
        loginUsr = loginPwd = emailAuth = captcha = captchaGID = ""
        unhandledFailed = False #Some failure we have not planend for
        while True: #While not success in response
            print("You are currently not logged in")
            
            if not respLogin or respLogin and not respLogin["success"] and False: #TODO: Incorrect credentials
                loginUsr = input("Username: ")
                loginPwd = input("Password: ")
                unhandledFailure = False
            
            if respLogin and not respLogin["success"]:
                if "emailauth_needed" in respLogin and respLogin["emailauth_needed"]:
                    emailAuth = input("Couldn't login, please provide email auth:")
                    unhandledFailure = False
                if "captcha_needed" in respLogin and respLogin["captcha_needed"]:
                    captchaGID = respLogin["captcha_gid"]
                    url = "https://steamcommunity.com/public/captcha.php?gid=" + captchaGID
                    webbrowser.open(url)
                    captcha = input("Captcha needed, displaying in webpage. Please type:")
                    unhandledFailure = False
            
            if unhandledFailure:
                print("Failure to login to Steam! Response: ")
                print(respLogin)
                raise RuntimeException("Steam login failed: " + str(respLogin))
            
            #Try a login
            respLogin = loginSteam(loginUsr, loginPwd, emailAuth, captcha, captchaGID, "", reqSession).json()
            
            #Save if success, otherwise try again and check for some other error
            if respLogin["success"]:
                #Write to file if we've got it!
                reqSession.cookies.save()
                break
            else:
                unhandledFailure = True
                
    return reqSession

def main(passwords, appIds):
    global requestDelay

    #Get a new steam session (Log in)
    reqSession = getNewSteamSession()

    #Sanity check
    print("Sanity check... ", end="")
    resp = hitSteamStore("94050999014715", "6900", reqSession).json()
    if not "response" in resp or resp["response"] != "ic/4f21ca7":
        print("FAILED!")
        if "response" in resp:
            print("Response was \"" + resp["response"] + "\" not \"ic/4f21ca7\"")
        else:
            print("Response was not present in json")
        raise RuntimeError("Sanity check failed.")
    
    print("SUCCESS")
    
    #Test passwords against all appIds
    appIdOffsetObj = 301242 #Offset by an appId value
    if appIdOffsetObj != 0:
        for i, id in enumerate(appIds):
            if appIdOffsetObj > int(id):
                appIdOffset = i
    appIdOffset = appIdOffset if appIdOffset != 0 else 0 #Offsets the first iteration by an index
    
    for pwd in passwords:
        print("["+pwd+"]")
        for i in range(appIdOffset,len(appIds)-1):
            id = appIds[i]
            print("_"+id, end="", flush=True)
            try:
                didWeGetSomethingOhBoy = hitSteamStore(pwd, id, reqSession).json()
            except Exception as e:
                print("->[ERROR]")
                option = input("Retry and continue with " + pwd + " @ " + id + " (Y/N)?")
                if re.search("^y$", option, re.I) == None:
                    raise
                else:
                    import traceback
                    print(traceback.format_exc())
                    i = i-1
                
            if(didWeGetSomethingOhBoy != []):
                #Holy shit sholthahdsoajr2
                print("") #Newline
                logPrint("[Found]: " + didWeGetSomethingOhBoy)
            
            #Delay between sends
            time.sleep(requestDelay)
        
        appIdOffset = 0 #Only offset the first iteration
    
if __name__ == "__main__":
    #Get app ids from xPaw
    appIds = requests.request("GET","https://s.xpaw.me/appids_with_prices.txt").text
    appIds = re.split("\\r?\\n", appIds)
    appIds[:] = [id for id in appIds if re.search("^\\d+$", id) != None]
    
    
    
    main(passwords, appIds)
    