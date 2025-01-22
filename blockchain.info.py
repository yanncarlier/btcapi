'''
https://www.blockchain.com/explorer/api/q
'''
import http.client
conn = http.client.HTTPSConnection("blockchain.info")
payload = ''
headers = {
  }
conn.request("GET", "/q/addressbalance/1EzwoHtiXB4iFwedPr49iywjZn2nnekhoj", payload, headers)
res = conn.getresponse()
data = res.read()
print(data.decode("utf-8"))