from fake_useragent import UserAgent
from requests import get
from random import shuffle, randrange
from bs4 import BeautifulSoup as bs


"""
All credits to this post:
https://github.com/eneyi/Exploits-Db/blob/master/security.py

"""

#this function creates a fake user client on each use request
def spoofme():
    ua = UserAgent()
    chrome = ua.data['browsers']['chrome'][5:40]
    shuffle(chrome)
    pick = chrome[randrange(1,len(chrome))]
    return pick



##this function accesses a url and return a soup object
def getPage(url):
    try:
        req = get(url, headers={'user-agent':spoofme()}).content
        soup = bs(req, "html.parser")
    except:
        soup = ""
    return soup


