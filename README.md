# Vulnezer-Prioritization_of_vulnerabilities
Python program for prioritising vulnerabilities found using a framework that utilises CVSS, KEV, and EPSS. 
The program offers an improved approach compared to the classic CVSS.
<img width="999" height="558" alt="image" src="https://github.com/user-attachments/assets/e8d133ac-491a-4189-8819-0f4066649743" />



Confirmed CVSS problems are:

• Duplication: Many vulnerabilities have identical CVSS ratings, limiting prioritisation precision.

• Inconsistency: Different platforms and versions of CVSS gave different severity ratings.

• Human factors: The CVSS rating is based on subjective interpretations by assessors, which leads to inconsistencies.

• Limited scope: CVSS does not reflect real-world exploit trends or attack likelihood.


How Vulnezer solves these problems - it reflects real evidence of exploitation (KEV) and the probability of a vulnerability being exploited in the next 30 days (EPSS). This gives you a real, numerical, unique value that characterises the actual risk, not just the severity according to CVSS.
<img width="780" height="487" alt="image" src="https://github.com/user-attachments/assets/c77e0bec-93db-4f93-beac-46fb893869ba" />


Vulnezer is a simple, transparent, and understandable program. Less than 10 megabytes in size, it can be installed on any device, and you can change the weight of the coefficients depending on your strategy. The framework has an academic background, in particular on official reports from Cisco.

3 simple steps:

 1) Scan your potentially vulnerable object with any scanner.

 2) Enter this data into Vulnezer (manually or CSV).

 3) Get the final result of the sequence for correction based on a composite formula (CVSS, EPSS, and KEV).
<img width="592" height="370" alt="image" src="https://github.com/user-attachments/assets/71a8bb6c-c996-44a5-b00a-278367fb48a3" />
As a result, you receive a clear order of vulnerability remediation — notifications about vulnerabilities that require attention according to the PCI DSS standard or if they have evidence of exploitation and are therefore recommended for remediation in the near future (30 days). 

<img width="2530" height="1109" alt="image" src="https://github.com/user-attachments/assets/f7c354ad-b974-4ed4-98b3-1f4f9c7175b4" />

To work, you will need API keys from NVD (https://nvd.nist.gov/developers/request-an-api-key) and Vulnercheck (https://www.vulncheck.com/). Just paste them into the .env file.

Happy vulnerability fixing!

