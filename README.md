# Vulnezer-Prioritization_of_vulnerabilities
Python program for prioritising vulnerabilities found using a framework that utilises CVSS, KEV, and EPSS. 
The program offers an improved approach compared to the classic CVSS.
<img width="1464" height="817" alt="image" src="https://github.com/user-attachments/assets/628de235-f04d-49bd-aa83-10d7d7367f73" />

Confirmed CVSS problems are:

• Duplication: Many vulnerabilities have identical CVSS ratings, limiting prioritisation precision.

• Inconsistency: Different platforms and versions of CVSS gave different severity ratings.

• Human factors: The CVSS rating is based on subjective interpretations by assessors, which leads to inconsistencies.

• Limited scope: CVSS does not reflect real-world exploit trends or attack likelihood.


How Vulnezer solves these problems - it reflects real evidence of exploitation (KEV) and the probability of a vulnerability being exploited in the next 30 days (EPSS). This gives you a real, numerical, unique value that characterises the actual risk, not just the severity according to CVSS.


<img width="2530" height="1109" alt="image" src="https://github.com/user-attachments/assets/f7c354ad-b974-4ed4-98b3-1f4f9c7175b4" />

Vulnezer is a simple, transparent, and understandable program. Less than 10 megabytes in size, it can be installed on any device, and you can change the weight of the coefficients depending on your strategy. The framework has an academic background, in particular on official reports from Cisco.
<img width="1062" height="667" alt="image" src="https://github.com/user-attachments/assets/e1ef503f-6679-4d21-8e22-17cd279d5b54" />
3 simple steps:

 1) Scan your potentially vulnerable object with any scanner.

 2) Enter this data into Vulnezer (manually or CSV).

 3) Get the final result of the sequence for correction based on a composite formula (CVSS, EPSS, and KEV).
<img width="700" height="431" alt="image" src="https://github.com/user-attachments/assets/0c562821-72bb-474a-aaee-404a36f0cd36" />
