import json
import os
import pandas as pd
import numpy as np

def getCVEItemLabels(cve_item):
    
    """
    Reads a CVE item from a JSON file
    """
    cve_item_dict = dict()
    
    #data type
    cve_item_dict['data_type'] = cve_item['cve']['data_type']
    #format
    cve_item_dict['data_format'] = cve_item['cve']['data_format']
    #version
    cve_item_dict['data_version'] = cve_item['cve']['data_version']
    
    #unique id
    cve_item_dict['ID'] = cve_item['cve']['CVE_data_meta']['ID']
    
    #assigner
    cve_item_dict['assigner'] = cve_item['cve']['CVE_data_meta']['ASSIGNER']
    
    #language of description of problem type
    #note that problemtype_data contains a list such that multiple CWEs might be present
    cwe_val = []
    for problemtype_data in cve_item['cve']['problemtype']['problemtype_data']:
        for description in problemtype_data['description']:
            cwe_val.append(description['value'])
        
    cve_item_dict['cwe_val'] = cwe_val
        
    
    #add all desciptions into one string
    description_string = ''
    for description_data in cve_item['cve']['description']['description_data']:
        description_string += description_data['value'] +'\n'
        
    cve_item_dict['description'] = description_string
    
    return cve_item_dict


def getCVEV3Tags(cve_item):
    cve_item_dict = dict()
    
    
     #vector string
    try:
        cve_item_dict['vectorString_V3'] = cve_item['impact']['baseMetricV3']['cvssV3']['vectorString']
    except KeyError:
        cve_item_dict['vectorString_V3'] = None
        
        
    try:
        cve_item_dict['attackVector_V3'] = cve_item['impact']['baseMetricV3']['cvssV3']['attackVector']
    except KeyError:
        cve_item_dict['attackVector_V3'] = None
        
        
    try:
        cve_item_dict['attackComplexity_V3'] = cve_item['impact']['baseMetricV3']['cvssV3']['attackComplexity']
    except KeyError:
        cve_item_dict['attackComplexity_V3'] = None
        
        
    try:
        cve_item_dict['privilegesRequired_V3'] = cve_item['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
    except KeyError:
        cve_item_dict['privilegesRequired_V3'] = None
        
    try:
        cve_item_dict['userInteraction_V3'] = cve_item['impact']['baseMetricV3']['cvssV3']['userInteraction']
    except KeyError:
        cve_item_dict['userInteraction_V3'] = None
        
    try:
        cve_item_dict['scope_V3'] = cve_item['impact']['baseMetricV3']['cvssV3']['scope']
    except KeyError:
        cve_item_dict['scope_V3'] = None
    
    try:
        cve_item_dict['confidentialityImpact_V3'] = cve_item['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
    except KeyError:
        cve_item_dict['confidentialityImpact_V3'] = None
    
    
    try:
        cve_item_dict['integrityImpact_V3'] = cve_item['impact']['baseMetricV3']['cvssV3']['integrityImpact']
    except KeyError:
        cve_item_dict['integrityImpact_V3'] = None
        
    try:
        cve_item_dict['availabilityImpact_V3'] = cve_item['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
    except KeyError:
        cve_item_dict['availabilityImpact_V3'] = None
        
    try:
        cve_item_dict['baseScore_V3'] = cve_item['impact']['baseMetricV3']['cvssV3']['baseScore']
    except KeyError:
        cve_item_dict['baseScore_V3'] = None
        
    try:
        cve_item_dict['baseSeverity_V3'] = cve_item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
    except KeyError:
        cve_item_dict['baseSeverity_V3'] = None
        
        
    try:
        cve_item_dict['exploitabilityScore_V3'] = cve_item['impact']['baseMetricV3']['exploitabilityScore']
    except KeyError:
        cve_item_dict['exploitabilityScore_V3'] = None
        
    try:
        cve_item_dict['impactScore_V3'] = cve_item['impact']['baseMetricV3']['impactScore']
    except KeyError:
        cve_item_dict['impactScore_V3'] = None
        
        
    return cve_item_dict

def getCVEV2Tags(cve_item):
    cve_item_dict = dict()
    
    try:
        cve_item_dict['vectorString_V2'] = cve_item['impact']['baseMetricV2']['cvssV2']['vectorString']
    except KeyError:
        cve_item_dict['vectorString_V2'] = None
        
        
    try:
        cve_item_dict['accessVector_V2'] = cve_item['impact']['baseMetricV2']['cvssV2']['accessVector']
    except KeyError:
        cve_item_dict['accessVector_V2'] = None
        
        
    try:
        cve_item_dict['accessComplexity_V2'] = cve_item['impact']['baseMetricV2']['cvssV2']['accessComplexity']
    except KeyError:
        cve_item_dict['accessComplexity_V2'] = None
        
        
    try:
        cve_item_dict['authentication_V2'] = cve_item['impact']['baseMetricV2']['cvssV2']['authentication']
    except KeyError:
        cve_item_dict['authentication_V2'] = None
        
        
    try:
        cve_item_dict['confidentialityImpact_V2'] = cve_item['impact']['baseMetricV2']['cvssV2']['confidentialityImpact']
    except KeyError:
        cve_item_dict['confidentialityImpact_V2'] = None
        
        
    try:
        cve_item_dict['integrityImpact_V2'] = cve_item['impact']['baseMetricV2']['cvssV2']['integrityImpact']
    except KeyError:
        cve_item_dict['integrityImpact_V2'] = None
        
        
    try:
        cve_item_dict['availabilityImpact_V2'] = cve_item['impact']['baseMetricV2']['cvssV2']['availabilityImpact']
    except KeyError:
        cve_item_dict['availabilityImpact_V2'] = None
        
        
    try:
        cve_item_dict['baseScore_V2'] = cve_item['impact']['baseMetricV2']['cvssV2']['baseScore']
    except KeyError:
        cve_item_dict['baseScore_V2'] = None
        
        
    try:
        cve_item_dict['vectorString_V2'] = cve_item['impact']['baseMetricV2']['cvssV2']['vectorString']
    except KeyError:
        cve_item_dict['vectorString_V2'] = None
        
        
    try:
        cve_item_dict['severity_V2'] = cve_item['impact']['baseMetricV2']['severity']
    except KeyError:
        cve_item_dict['severity_V2'] = None
        
        
    try:
        cve_item_dict['exploitabilityScore_V2'] = cve_item['impact']['baseMetricV2']['exploitabilityScore']
    except KeyError:
        cve_item_dict['exploitabilityScore_V2'] = None
        
        
    try:
        cve_item_dict['impactScore_V2'] = cve_item['impact']['baseMetricV2']['impactScore']
    except KeyError:
        cve_item_dict['impactScore_V2'] = None
        
        
    try:
        cve_item_dict['acInsufInfo_V2'] = cve_item['impact']['baseMetricV2']['acInsufInfo']
    except KeyError:
        cve_item_dict['acInsufInfo_V2'] = None
        
        
    try:
        cve_item_dict['obtainAllPrivilege_V2'] = cve_item['impact']['baseMetricV2']['obtainAllPrivilege']
    except KeyError:
        cve_item_dict['obtainAllPrivilege_V2'] = None
        
        
    try:
        cve_item_dict['obtainUserPrivilege_V2'] = cve_item['impact']['baseMetricV2']['obtainUserPrivilege']
    except KeyError:
        cve_item_dict['obtainUserPrivilege_V2'] = None
        
        
    try:
        cve_item_dict['obtainOtherPrivilege_V2'] = cve_item['impact']['baseMetricV2']['obtainOtherPrivilege']
    except KeyError:
        cve_item_dict['obtainOtherPrivilege_V2'] = None
        
        
    try:
        cve_item_dict['userInteractionRequired_V2'] = cve_item['impact']['baseMetricV2']['userInteractionRequired']
    except KeyError:
        cve_item_dict['userInteractionRequired_V2'] = None
        
        
    return cve_item_dict
    
    
def getCVETemporalData(cve_item):
    
    cve_item_dict = dict()
    
    try:
        cve_item_dict['publishedDate'] = cve_item['publishedDate']
    except KeyError:
        cve_item_dict['publishedDate'] = None
        
        
    try:
        cve_item_dict['lastModifiedDate'] = cve_item['lastModifiedDate']
    except KeyError:
        cve_item_dict['lastModifiedDate'] = None
    
    return cve_item_dict



def getCVEAsDict(cve_item):
    
    cve_item_dict_labels = getCVEItemLabels(cve_item)
    cve_item_dict_v3 = getCVEV3Tags(cve_item)
    cve_item_dict_v2 = getCVEV2Tags(cve_item)
    cve_item_dict_temporal = getCVETemporalData(cve_item)
    
    
    #combine multiple dicts
    #can use | but not running python 3.9
    cve_item_dict = {**cve_item_dict_labels,  **cve_item_dict_v3, **cve_item_dict_v2, **cve_item_dict_temporal}
    
    return cve_item_dict
    
    
def main():
    
    #store new csv files in combined one
    csv_arr = []
    
    for i in range(2,21,1):
        #make i a string and add to names
        
        print("Acessing file ... {}".format('nvdcve-1.1-' +str(2000+i) + '.json'))
        file = os.path.join('data', 'nvdcve-1.1-' +str(2000+i) + '.json')
        
        with open(file) as f:
            data = json.load(f)
            
            
        #array to store cve items
        cve_item_array = []
        
        #loop over all CVEs in dict
        for cve_item in data['CVE_Items']:

            cve_item_dict = getCVEAsDict(cve_item)
            cve_item_array.append(cve_item_dict)
            
        # create dataframe from files
        df_cve = pd.DataFrame(cve_item_array)
        
        #fixes issue where cwe_val column has 2+ entries
        df_cve = df_cve.explode('cwe_val')
        
        csv_arr.append(df_cve)
              
        print("Saving to file... {}".format('nvdcve-1.1-' +str(2000+i) + '.csv'))
        df_cve.to_csv(os.path.join('data', 'nvdcve-1.1-' +str(2000+i) + '.csv'), index=False)
        
    combined_csv = pd.concat(csv_arr)
    
    print("Saving combined csv to... {}".format(os.path.join('data','nvdcve_combined.csv')))
    combined_csv.to_csv(os.path.join('data','nvdcve_combined.csv'),
                        index=False)
    print("... DONE! EXITING PROGRAM! ...")
        


if __name__ == '__main__':
    main()

        


