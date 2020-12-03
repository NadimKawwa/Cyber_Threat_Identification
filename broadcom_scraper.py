import os
import glob
import pandas as pd
from selenium import webdriver
import time
import copy
import warnings
warnings.filterwarnings('ignore')
import pickle



def save_obj(obj, path ):
    with open(path, 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)
        
def load_obj(path ):
    with open(path, 'rb') as f:
        return pickle.load(f)

def getPageSource(url, snooze_time=5):
    """
    creaters a web driver with selenium
    reads and runs javascript on page
    returns plain text of page
    """
    #instantiate driver
    driver = webdriver.PhantomJS()
    #get url
    print("reading from... {}".format(url))
    driver.get(url)
    #sleep
    time.sleep(snooze_time)
    print("sleeping for {} seconds...".format(snooze_time))
    #page source
    htmlSource = driver.page_source
    
    #quit the driver
    driver.quit()
    
    return htmlSource



def cleanText(html_text):
    """
    brute force cleaning of text
    replaces certain characters with space
    returns a copy of the text
    """
    text = copy.copy(html_text)
    text = text.replace('[', ' ').replace(']', ' ').replace('<', ' ').replace('>', ' ').replace('.', ' ')
    text = text.replace('=', ' ').replace('"',' ').replace(',', ' ').replace(r'/', '-').replace("\\","-")
    
    return text



def cve_harvest(text):
    """
    looks for anything with 'CVE' inside a text and returns a list of it
    """
    array = []
    #look inside split by whitespace
    for word in text.split():
        if 'CVE' in word:
            array.append(word)
    return array



def main():
        
    df_path = os.path.join('data', 'attack_signatures.csv')
    df = pd.read_csv(df_path, index_col=0)
    
    assert df['title'].nunique() == df.shape[0], "no duplicate titles allowed"
    
    for i in df.index:
        #go over each row in dataframe
        row = df.iloc[i,:]
        #get title and url
        url = row['url']
        title = row['title']
        
        #replace any slashes with "-"
        title = title.replace(r'/', '-').replace("\\","-")
        asid = url.split('=')[-1]
        
        #path where dict will be saved
        path = os.path.join('broadcom_dicts', asid+'.pkl')
        
        if not os.path.isfile(path):
            #instantiate empty dict
            cve_dict = {}
            #get page source
            htmlSource = getPageSource(url)
            #get the text in cleaned format
            text = cleanText(htmlSource)
            #get all ceves
            cve_list = cve_harvest(text)
            
            #populate attack signature id
            cve_dict['asid'] = asid
            #populate title
            cve_dict['title'] = title
            #populate url
            cve_dict['url'] = url
            #populate CVE list
            cve_dict['CVE'] = cve_list
            
            
            #save the work
            print('saving to... {}'.format(path))
            save_obj(obj = cve_dict, path = path)
            
        else:
            print('{} already existits... skipping file'.format(title))
        


        
if __name__ == "__main__":
    main()
        
    
    
    
    
    





