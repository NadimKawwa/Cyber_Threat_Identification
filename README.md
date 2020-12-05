# Cybersecurity Threat Identification

![Security Cameras](https://github.com/NadimKawwa/Cyber_Threat_Identification/blob/main/plots/banner_image.jpeg)

## Objective
This repository leverages data science and machine learning to answer the question:
#### Can we correctly label critical vulnerabilities  with an ML model?

## Data

Cybersecurity is an amazingly broad field. The data is vast and it is also very scattered. 
The sources used here are:
- National vulnerability database
- Exploit DB
- Symantec
- CISA
- Google searches here and there :) 

This is an imbalanced classification problem and is illustrated in the Venn diagram below.
![Venn Diagram](https://github.com/NadimKawwa/Cyber_Threat_Identification/blob/main/plots/venn_diagram.png)

## Workflow 
The jupyter notebooks in the reposiroty are sequentially numbered to give an idea of how to proceed. The workflow is summarized in the figure below.

![Vertical Workflow](https://github.com/NadimKawwa/Cyber_Threat_Identification/blob/main/plots/flow_vertical.png)

For the ML model i used XGBoost and for text data processing I used a TF-IDF Vectorizer. Note that we need to make use of a pipeline since we are dealing with heterogenous data. Moreover, this prevents any data leakage while doing the cross validated grid search.

## Metrics

We can achieve a decent ROC of 0.87. However, it depends what we are looking for as different organizations will have different goals and capabilities.

### Precision
Precision determines how many selected items are relevant:
If we want better precision we need to have as few false positives as possible. Therefore, an efficient model will have high precision, and allocates time and resources only to vulnerabilities that require patching.

### Recall
Recall poses the question: How many relevant items are selected? A perfect recall score of 1.0 implies no false negatives were selected. In the context of this project, the recall determines how many vulnerabilities that should be remediated have been flagged.

## Results

We fit a grid search cross validation to optimize for a set of success metrics. The results are summarized in the table and plots below.

![grid search cv metrics](https://github.com/NadimKawwa/Cyber_Threat_Identification/blob/main/plots/metric_comparison.JPG)

![prc curve](https://github.com/NadimKawwa/Cyber_Threat_Identification/blob/main/plots/PRC_All_Metrics.png)

![roc curve](https://github.com/NadimKawwa/Cyber_Threat_Identification/blob/main/plots/ROC_All_Metrics.png)


Moreover, I conducted a bootstrapping experiment to see how reliable are the results. 
95% of the time, the precision will be in **(0.149, 0.234)**, for recall it is **(0.333, 0.55)**, and for F1 it is **(0.180, 0.337)**. 

![precision recall histogram](https://github.com/NadimKawwa/Cyber_Threat_Identification/blob/plot_update/plots/precision_recall_hist.png)

## Conclusion

It's crucial to state that the findings here might be challenged in the future as new data becomes available. This project also omits existing defense mechanisms organizations might have, and only takes a bird's eye view of things. To put it plainly: your mileage may vary based on how secure your defenses are and on the jackpot in your safe.
Furthermore, this project does not take into account the effect of time. Indeed, some CVEs might already have an existing patch, which may or many not have been implemented. It is also possible that with more sophisticated tools and higher computing power, previous innocuous CVEs can wreak havoc on an organization.
With a rather simple workflow, critical vulnerabilities can be identified with a relatively high performance. This means that as new CVEs are released on NVD, a ML model can be used to evaluate if they are likely to be exploited in the wild.
