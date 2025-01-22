'''
https://www.blockcypher.com/dev/bitcoin/?shell#address-balance-endpoint
'''
import http.client
conn = http.client.HTTPSConnection("api.blockcypher.com")
payload = ''
headers = {
  }
conn.request("GET", "/v1/btc/main/addrs/1EzwoHtiXB4iFwedPr49iywjZn2nnekhoj", payload, headers)
res = conn.getresponse()
data = res.read()
print(data.decode("utf-8"))