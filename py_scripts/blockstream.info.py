'''
https://github.com/Blockstream/esplora/blob/master/API.md
'''
import http.client
conn = http.client.HTTPSConnection("blockstream.info")
payload = ''
headers = {}
conn.request("GET", "/api/address/bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", payload, headers)
res = conn.getresponse()
data = res.read()
print(data.decode("utf-8"))