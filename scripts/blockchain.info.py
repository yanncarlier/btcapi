'''
https://www.blockchain.com/explorer/api/q
'''
import http.client
conn = http.client.HTTPSConnection("blockchain.info")
payload = ''
headers = {
  }
conn.request("GET", "/q/addressbalance/bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", payload, headers)
res = conn.getresponse()
data = res.read()
print(data.decode("utf-8"))