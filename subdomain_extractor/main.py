import os
from extractor import Sensitive_Info_Extractor

# Here is the Sensitive_Info_Extractor class calling and these are list of subsomain that are passing to function
# Add your list of subdomains here
subdomains = ['subdomain1.example.com', 'subdomain2.example.com', 'subdomain3.example.com']
sensitive_info = Sensitive_Info_Extractor(subdomains)