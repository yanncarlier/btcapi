'''
https://github.com/Blockstream/esplora/blob/master/API.md
'''
import http.client
conn = http.client.HTTPSConnection("blockstream.info")
payload = ''
headers = {}
conn.request("GET", "/api/address/1EzwoHtiXB4iFwedPr49iywjZn2nnekhoj", payload, headers)
res = conn.getresponse()
data = res.read()
print(data.decode("utf-8"))