#Steam market bruteforcer for winter games 2016
#Author: Coburn

import gzip
import json
import time
import os
import sys
import webbrowser
from http.cookiejar import LWPCookieJar
#You need pyCrypto to use this (this is a PAIN IN THE ASS on Windows :c but there are prebuilt binaries available )
import Crypto
#Also you need requests
import requests

logFile = os.path.abspath("./log.txt")
logFile = open(logFile, 'a')

def logPrint(myStr):
    global logFile
    print(myStr)
    logFile.write(myStr)

user_agent = "Steam Winter Sale 2015_16 Python Crawler"
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

cookieFile = "loginCookies.txt"
reqSession = None
def hitSteamStore(pwd, appId):
    global cookieFile
    global user_agent
    global reqSession
    
    #GET LOGIN COOKIE TO ACTUALLY QUERY THE STORE FROM AN ACCOUNT
    if not reqSession:
        #Check if the old one exists and
        #Only use if new enough (4 hours was an arbitrary choice)
        if os.path.isfile(cookieFile) and time.time() > float(os.path.getmtime(cookieFile)) + (60*60*4):
            reqSession = requests.Session()
            tmpCookieJar = LWPCookieJar(cookieFile)
            reqSession.cookies = tmpCookieJar.load()
            
        #Otherwise Get a new login cookie
        else:
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
                respLogin = loginSteam(loginUsr, loginPwd, emailAuth, captcha, captchaGID, reqSession).json()
                
                #Save if success, otherwise try again and check for some other error
                if respLogin["success"]:
                    #Write to file if we've got it!
                    reqSession.cookies.save(cookieFile)
                    break
                else:
                    unhandledFailure = True
        
    #ACTUALLY DO A REQUEST
    url = "http://store.steampowered.com/actions/clues"
    values = { "key" : pwd }
    headers = {
        "Referer":"http://store.steampowered.com/app/"+appId+"/", #Referrer AppID we're looking at
        "User-Agent" : user_agent
    }
    resp = reqSession.request("POST", url, data=values, headers=headers)
    
    return resp


def main():
    #Your passwords to check go here!
    passwods = []
    #We need to retrieve a list of all the AppIds
    appIds = requests.get("GET", "https://s.xpaw.me/appids_with_prices.txt").text.split("\n")
    
    #Test passwords against all appIds
    for pwd in passwords:
        for id in appIds:
            didWeGetSomethingOhBoy = hitSteamStore(pwd, "222621")
            if(didWeGetSomethingOhBoy != "[]"):
                #Holy shit sholthahdsoajr2
                logPrint("[Found]: " + didWeGetSomethingOhBoy)
    
if __name__ == "__main__":
    main()
    