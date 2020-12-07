import pandas as pd
import numpy as np
import os
from time import time
import pickle

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import GridSearchCV
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer, make_column_selector, make_column_transformer
from sklearn.preprocessing import MinMaxScaler
import xgboost as xgb


#should find a way to import utils without error
def save_obj(obj, path ):
    with open(path, 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)
        
def load_obj(path ):
    with open(path, 'rb') as f:
        return pickle.load(f)

def getData():
    """
    Loads train data
    """
    
    X_train = load_obj(path=os.path.join('data_processed', 'X_train.pkl'))
    y_train = load_obj(path=os.path.join('data_processed', 'y_train.pkl'))
    
    return X_train, y_train


def createPipeline(y_train):
    """
    Returns a sklearn pipeline
    """
    
    
    #Control the balance of positive and negative weights, useful for unbalanced classes
    #A typical value to consider:
    # sum(negative instances) / sum(positive instances)
    scale_pos_weight = float(np.sum(y_train == 0)) / np.sum(y_train == 1)

    
    #define preprocessor
    preprocessor = ColumnTransformer([('tfidfvect',
                               TfidfVectorizer(ngram_range=(1,3),
                                               stop_words='english'), 
                               'description' #apply transformation to this column
                                      )
                             ],
                             remainder=MinMaxScaler(),
                             n_jobs=-1
                            )

    #define pipeline
    pipeline = Pipeline(steps=[('preprocessor', preprocessor),
                          ('clf', xgb.XGBClassifier(n_estimators=100,
                                                    scale_pos_weight = scale_pos_weight,
                                                    eta=0.9,
                                                    num_boost_round=15,
                                                   )
                          )
                              ])
    return pipeline

def getStats(grid_search, parameters):
    
    print(20*'#')
    print(20*'#')
    print('\n')
    
    print("Best score: %0.3f" % grid_search.best_score_)
    print('\n')
    print(20*'#')
    print('\n')
    print("Best parameters set:")
    best_parameters = grid_search.best_estimator_.get_params()
    for param_name in sorted(parameters.keys()):
        print("\t%s: %r" % (param_name, best_parameters[param_name]))
        
    print('\n')
    print(20*'#')
    print(20*'#')


def grid_fitting(pipeline, X_train, y_train,scoring='roc_auc'):
    #params for grird search
    #note the double __ to get to nested elements
    parameters = {
        'preprocessor__tfidfvect__max_df': (0.8, 0.9),
        'preprocessor__tfidfvect__min_df': (0.1, 0.15),
        'preprocessor__tfidfvect__max_features': (200, 250),
        'clf__max_depth': (6, 12), #Maximum depth of a tree. Increasing this value will make the model more complex and more likely to overfit
        'clf__subsample': (0.5, 0.9) #take part of train data to avoid overfitting

    }

    #instantiate grid search
    grid_search = GridSearchCV(pipeline, 
                               parameters, 
                               n_jobs=-1, 
                               verbose=10, #lots of details
                               scoring=scoring,
                               #refit='roc_auc', 
                               return_train_score=True
                              )
    
    #place where we will save artifact
    path = os.path.join('artifacts','grid_search_2020-11-29_'+scoring+'.pkl')
    
    if not os.path.isfile(path):
        # start the timer
        t0 = time()
        print("Fitting for {}".format(scoring))
        #begin fitting
        grid_search.fit(X_train, y_train)

        #get stats
        getStats(grid_search, parameters)
        #save the object
        save_obj(obj = grid_search,
                       path = path)
        print("Saving to... {}".format(path))
        
        #time to do it
        print("done in %0.3fs" % (time() - t0))
        
    else:
        print("{} already exists... skipping".format(path))
    
    
    
    
def main():
    
    

    print(50*'=')
    print('\n')
    print('\n')
    print('\n')
    print('\n')
    
    #load train data
    X_train, y_train = getData()
    
    scoring_array = ['roc_auc', 'f1', 'precision', 'recall', 'average_precision']
    
    for scoring in scoring_array:
        
        #instantiate a pipeline
        pipeline = createPipeline(y_train)
        grid_fitting(pipeline= pipeline, X_train= X_train, y_train= y_train, scoring=scoring)
        
    print('\n')
    print('\n')
    print('\n')
    print('\n')
    print(50*'=')
        
        
        
if __name__ == "__main__":
    main()
        
        
    
    
    