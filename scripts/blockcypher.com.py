'''
https://www.blockcypher.com/dev/bitcoin/?shell#address-balance-endpoint
'''
import http.client
conn = http.client.HTTPSConnection("api.blockcypher.com")
payload = ''
headers = {
  }
conn.request("GET", "/v1/btc/main/addrs/bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", payload, headers)
res = conn.getresponse()
data = res.read()
print(data.decode("utf-8"))