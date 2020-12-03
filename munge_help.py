import pandas as pd
import numpy as np
import glob
import os
from collections import Counter
import pickle
from tqdm import tqdm


"""
Collection of functions used before EDA to convert data into 

"""

def infer_dtypes(df):
    
    """
    Infers the types of a NVD dataframe
    """
    
    #make deep copy
    df_nvd = df.copy(deep=True)
    
    #make dtype of times as datetime
    df_nvd['publishedDate'] = pd.to_datetime(df_nvd['publishedDate'],
                                         infer_datetime_format=True)
    
    df_nvd['lastModifiedDate'] = pd.to_datetime(df_nvd['lastModifiedDate'],
                                        infer_datetime_format=True)
    
    
    #let pandas infer remainder of types
    #note that function has no argument for time series
    df_nvd = df_nvd.convert_dtypes(infer_objects=True, 
                           convert_string=False, 
                           convert_integer=True, 
                           convert_boolean=True)
    
    
    #get columms that re bool
    df_bool_cols = df_nvd.select_dtypes(include=bool).columns

    #change boolean columns to 1/0 integer
    df_nvd[df_bool_cols] *= 1
    
    return df_nvd
    
    
def categorical_to_numerical(df):
    """
    Takes in a pandas dataframe from NVD data and converts it to nemrical where possible
    columns are predefined
    In some cases will fill NaN with 0
    """
    
    #create a deep copy and work on it
    df_num = df.copy()
    
    
    #drop columns with single values
    
    df_num = df_num.drop(columns=['data_type', 'data_format', 'data_version', 'assigner'])
    
    #instantiate dicts
    accessComplexity_V2_dict = {np.nan:0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
    authentication_V2_dict = {'NONE': 0, np.nan: 0, 'SINGLE': 1, 'MULTIPLE': 2}
    confidentialityImpact_V2_dict = {'NONE': 0, np.nan: 0, 'PARTIAL': 1, 'COMPLETE': 2}
    integrityImpact_V2_dict = {'NONE': 0, np.nan: 0, 'PARTIAL': 1, 'COMPLETE': 2}
    availabilityImpact_V2_dict = {'NONE': 0, np.nan: 0, 'PARTIAL': 1, 'COMPLETE': 2}
    severity_V2_dict = {np.nan:0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
    attackComplexity_V3_dict = {np.nan: 0, 'LOW': 1, 'HIGH': 2}
    privilegesRequired_V3_dict = {np.nan: 0, 'NONE': 0, 'LOW': 1, 'HIGH': 1}
    userInteraction_V3_dict = {np.nan: 0, 'NONE': 0, 'REQUIRED': 1}
    scope_V3_dict = {np.nan: 0, 'UNCHANGED': 0, 'CHANGED': 1}
    confidentialityImpact_V3_dict = {np.nan: 0 , 'NONE': 0, 'LOW': 1, 'HIGH': 2}
    integrityImpact_V3_dict = {np.nan: 0 , 'NONE': 0, 'LOW': 1, 'HIGH': 2}
    availabilityImpact_V3_dict = {np.nan: 0 , 'NONE': 0, 'LOW': 1, 'HIGH': 2}
    baseSeverity_V3_dict = {np.nan: 0 , 'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
    
    
    #new stuff added later in this project
    cwe_val_dict = {np.nan: '0'}
    vectorString_V3_dict = {np.nan: '0'}
    baseScore_V3_dict = {np.nan: 0}
    exploitabilityScore_V3_dict = {np.nan: 0}
    impactScore_V3_dict = {np.nan: 0}
    vectorString_V2_dict = {np.nan: '0'}
    baseScore_V2_dict = {np.nan: 0}
    exploitabilityScore_V2_dict = {np.nan: 0}        
    impactScore_V2_dict = {np.nan: 0}                   
    acInsufInfo_V2_dict = {np.nan: 0}                      
    obtainAllPrivilege_V2_dict = {np.nan: 0}               
    obtainUserPrivilege_V2_dict = {np.nan: 0}              
    obtainOtherPrivilege_V2_dict = {np.nan: 0}            
    userInteractionRequired_V2_dict = {np.nan: 0}    
    
    
    
    
    df_num.replace(to_replace = {'accessComplexity_V2': accessComplexity_V2_dict,
                                 'authentication_V2': authentication_V2_dict, 
                                 'confidentialityImpact_V2': confidentialityImpact_V2_dict, 
                                 'integrityImpact_V2' : integrityImpact_V2_dict, 
                                 'availabilityImpact_V2': availabilityImpact_V2_dict, 
                                 'severity_V2': severity_V2_dict, 
                                 'attackComplexity_V3': attackComplexity_V3_dict, 
                                 'privilegesRequired_V3': privilegesRequired_V3_dict, 
                                 'userInteraction_V3' : userInteraction_V3_dict, 
                                 'scope_V3': scope_V3_dict, 
                                 'confidentialityImpact_V3' : confidentialityImpact_V3_dict, 
                                 'integrityImpact_V3': integrityImpact_V3_dict,
                                 'availabilityImpact_V3': availabilityImpact_V3_dict, 
                                 'baseSeverity_V3': baseSeverity_V3_dict,
                                 'cwe_val': cwe_val_dict,
                                 'vectorString_V3': vectorString_V3_dict, 
                                 'baseScore_V3': baseScore_V3_dict,
                                 'exploitabilityScore_V3': exploitabilityScore_V3_dict, 
                                 'impactScore_V3': impactScore_V3_dict, 
                                 'vectorString_V2': vectorString_V2_dict, 
                                 'baseScore_V2': baseScore_V2_dict, 
                                 'exploitabilityScore_V2': exploitabilityScore_V2_dict, 
                                 'impactScore_V2': impactScore_V2_dict, 
                                 'acInsufInfo_V2': acInsufInfo_V2_dict, 
                                 'obtainAllPrivilege_V2': obtainAllPrivilege_V2_dict, 
                                 'obtainUserPrivilege_V2': obtainUserPrivilege_V2_dict, 
                                 'obtainOtherPrivilege_V2': obtainOtherPrivilege_V2_dict, 
                                 'userInteractionRequired_V2': userInteractionRequired_V2_dict},
                   inplace=True)
    
    
    
    #one hot encode
    one_hot_df = pd.get_dummies(df_num['accessVector_V2'] , prefix='accessVector_V2')
    df_num = df_num.drop(columns = 'accessVector_V2')
    df_num = pd.merge(left = df_num, right=one_hot_df, right_index=True, left_index=True)
                  
    #repeat one hot for one more
    ### make function of it later
    
    
    one_hot_df = pd.get_dummies(df_num['attackVector_V3'] , prefix='attackVector_V3')
    df_num = df_num.drop(columns = 'attackVector_V3')
    df_num = pd.merge(left = df_num, right=one_hot_df, right_index=True, left_index=True)
    
    
    
    return df_num




def exploit_db_munger(exploitdb_df):
    #disregard URL and take CVE number only
    exploitdb_df['CVE'] = exploitdb_df['CVE'].str.split('/').str[-1]

    #boolean to integer
    exploitdb_df[exploitdb_df.select_dtypes(include=bool).columns] *= 1
    
    
    #one hot encode
    one_hot_df = pd.get_dummies(exploitdb_df['Type'] , prefix='Type')
    exploitdb_df = exploitdb_df.drop(columns = 'Type')
    exploitdb_df = pd.merge(left = exploitdb_df, right=one_hot_df, right_index=True, left_index=True)
    
    
    #one hot encode
    one_hot_df = pd.get_dummies(exploitdb_df['Platform'] , prefix='Type')
    exploitdb_df = exploitdb_df.drop(columns = 'Platform')
    exploitdb_df = pd.merge(left = exploitdb_df, right=one_hot_df, right_index=True, left_index=True)
    
    
    #get the rows where CVE is not NaN
    exploitdb_df = exploitdb_df[exploitdb_df['CVE'].notna()]

    
    return exploitdb_df
    
    

    
    
    