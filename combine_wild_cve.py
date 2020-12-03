import os
import glob
import pandas as pd
import numpy as np
from tqdm import tqdm
import pickle
from copy import copy


def load_obj(path ):
    with open(path, 'rb') as f:
        return pickle.load(f)


def main():
    """
    combines everything into one csv file
    """
    #reading from manually curated sources
    sources_with_data_text = os.path.join('data', 'sources_with_data.txt')
    with open (sources_with_data_text, mode='r') as f:
        lines = f.readlines()

    #check we closed the file
    assert f.closed

    #strip the spaces at the end
    lines = [l.strip() for l in lines]
    #keep only CVEs and drop the rest
    lines = [l for l in lines if 'CVE' in l]
    #remove redundants
    unique_cve = (set(lines))
    
    
    #create list of dicts
    broadcom_arr=[]
    for file in tqdm(glob.glob('broadcom_dicts/*.pkl')):
        obj = load_obj(file)
        #if array is not empty
        if obj['CVE']:
            broadcom_arr.extend(obj['CVE'])

    #make a set to remove duplicates
    broadcom_cve = (set(broadcom_arr))
    
    #make deep copy
    cve_in_wild = copy(broadcom_cve)
    #combine the two sets
    cve_in_wild.update(unique_cve)
    #some stats
    print("Found {} unique CVEs overall".format(len(cve_in_wild)))
    
    
    
    #########################################################################################
    #NOTE!!!!!
    # This section involves manual cleaning for data
    # Corrections for edge cases
    
    
    #fix some inconsistencies in data collection
    #manual fixes
    cve_in_wild = [cve.replace('1)', '') for cve in cve_in_wild]
    cve_in_wild = [cve.replace('service', '') for cve in cve_in_wild]
    cve_in_wild = [cve.replace('3)', '') for cve in cve_in_wild]
    cve_in_wild = [cve.replace('_3', '') for cve in cve_in_wild]
    cve_in_wild = [cve for cve in cve_in_wild if len(cve)>=11]
    cve_in_wild = [cve.replace('(', '') for cve in cve_in_wild]
    cve_in_wild = [cve.replace(')', '') for cve in cve_in_wild]


    ## more manual fixes to corrupted data
    cve_in_wild = [cve.replace('CVE2019-7278', 'CVE-2019-7278') for cve in cve_in_wild]
    cve_in_wild = [cve.replace('2CVE-2006-3643', 'CVE-2006-3643') for cve in cve_in_wild]
    cve_in_wild = [cve.replace('CVE2019-7279', 'CVE-2019-7279') for cve in cve_in_wild]
    cve_in_wild = [cve.replace('CVE-2018_16858', 'CVE-2018-16858') for cve in cve_in_wild]
    cve_in_wild = [cve.replace('CVE 2014-6278', 'CVE-2014-6278') for cve in cve_in_wild]
    cve_in_wild = [cve.replace('CVE-209-18935', 'CVE-2019-18935') for cve in cve_in_wild]
    cve_in_wild = [cve.replace('CVE_2009-3729', 'CVE-2009-3729') for cve in cve_in_wild]
    cve_in_wild = [cve.replace('CVE-20190-11539', 'CVE-2019-11539') for cve in cve_in_wild]
    cve_in_wild = [cve.replace('CVE-2190-11539', 'CVE-2019-11539') for cve in cve_in_wild]

    
    #########################################################################################
    
    
    
    #more stats
    dates = set([x.split('-')[1] for x in cve_in_wild])
    print("First exploit was recorded in {}".format(min(dates)))
    print("Last exploit was recorded in {}".format(max(dates)))
    
    #make empty dict to create target variable
    target_cve_dict = {}
    #read the main reference: NVD
    df_nvd = pd.read_csv(os.path.join('data', 'nvdcve_combined.csv'))
    #for each CVE
    for cve in df_nvd['ID']:
        if cve in cve_in_wild:
            target_cve_dict[cve] = 1
        else:
            target_cve_dict[cve] = 0

    #make adataframe
    df_target = pd.DataFrame.from_dict(target_cve_dict, orient='index', columns=['in_the_wild'])
    #index to column
    df_target['ID'] = df_target.index
    #drop index when done
    df_target = df_target.reset_index(drop=True)

    #rearrange
    df_target = df_target[['ID', 'in_the_wild']]
    
    #to csv
    save_path = os.path.join('data', 'target_cve.csv')
    
    
    df_target.to_csv(save_path, index=False)
    print("saved to... {}".format(save_path))


        
if __name__ == "__main__":
    main()
        
    

    
    
    
    