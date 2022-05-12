
from flask import Flask,redirect,request
import requests
import base64
import json

cliId=""
cliSecret=""
redirectUri="http://127.0.0.1:8080/authorization-code/callback"
# take the /v1/authorise part off to convert into the issuer url for
# provider configuration:
aznEndpoint="https://.../v1/authorize?"
tokenExchangeUrl="https://.../v1/token/?"
googProjectID="..."
wifPoolID="..."
wifProviderID="..."

def acTokenExchange():
   inputAznStr=cliId+":"+cliSecret
   strBytes=inputAznStr.encode("ascii")
   base64_bytes=base64.b64encode(strBytes)
   base64_str=base64_bytes.decode("ascii")
   secretHeaderString="Basic "+base64_str
   postHeaders={"accept": "application/json", "authorization": secretHeaderString, "content-type": "application/x-www-form-urlencoded"}
   try:
      postData="grant_type=authorization_code&redirect_uri=" + redirectUri + "&code=" + request.args.get('code')
   except:
      print("Failed to extract azn code")
   #postData="grant_type=authorization_code&redirect_uri=" + redirectUri + "&client_id=" +cliId +"&code=" + request.args.get('code')
   tokenResponse= requests.post(tokenExchangeUrl, data=postData, headers=postHeaders)
   jsonResponse = tokenResponse.json()
   return jsonResponse

def getStsToken(accessTkn):
   # attempt to make the packing of the dictionary tidy / readable:
   stsPostDict = {}
   stsPostDict.update({"audience": "//iam.googleapis.com/projects/"+googProjectID+"/locations/global/workloadIdentityPools/"+wifPoolID+"/providers/"+wifProviderID})
   stsPostDict.update({"grantType": "urn:ietf:params:oauth:grant-type:token-exchange"})
   stsPostDict.update({"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token"})
   stsPostDict.update({"scope": "https://www.googleapis.com/auth/cloud-platform"})
   stsPostDict.update({"subjectTokenType": "urn:ietf:params:oauth:token-type:jwt"})
   # this was id_token, which contains the default for the audience value. token picks up the custome azn server config:
   stsPostDict.update({"subjectToken": accessTkn})
   #print(json.dumps(stsPostDict))
   stsHeaders={"content-type": "text/json; charset=utf-8"}
   stsResp=requests.post("https://sts.googleapis.com/v1/token", data=json.dumps(stsPostDict), headers=stsHeaders)
   jsonSTS = stsResp.json()
   return jsonSTS

def getIamAPItken(stsTkn):
   iamAPI="https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"+"idp-test-svc-acc%40idp-test-349711.iam.gserviceaccount.com"+":generateAccessToken"
   iamHeaders={"Content-Type": "text/json; charset=utf-8", "Authorization": "Bearer "+ stsTkn}
   iamPostData={"scope": [ "https://www.googleapis.com/auth/cloud-platform" ]}
   print(json.dumps(iamPostData))
   iamResponse=requests.post(iamAPI, data=json.dumps(iamPostData), headers=iamHeaders)
   jsonIAM = iamResponse.json()
   return jsonIAM

app = Flask(__name__)

@app.route("/start")
def startFlow():
   # construct flow start - hardwiring a state parameter (oops)
   azReqUrl=aznEndpoint+"client_id=" + cliId + "&response_type=code&scope=openid&redirect_uri="+redirectUri+"&state=state-296bc9a0-a2a2-4a57-be1a-d0e2fd9bb601"
   return redirect(azReqUrl, code=302)

@app.route("/authorization-code/callback")
def aznStart():
   # attempt token exchange:
   exchangeResponseJson=acTokenExchange()
   try:
      accessTkn=exchangeResponseJson["access_token"]
   except:
      return("failed to extract access_token")

   # call to the google STS
   stsResponseJson=getStsToken(accessTkn)
   #trimmedToken = removeDots(jsonSTS["access_token"])
   try:
      stsTkn=stsResponseJson["access_token"]
      #print("sts token: ", stsTkn)
   except:
      return(stsResponseJson)

   # Use the token from the Security Token Service to invoke the generateAccessToken method of the IAM Service Account Credentials API to obtain an access token:
   # note the details in this answer for the structure of the path: https://stackoverflow.com/questions/59286935/calling-google-iam-generateaccesstoken-api-always-returns-error
   
   iamAPItkn=getIamAPItken(stsTkn)
   return(iamAPItkn)


if __name__ == '__main__':
   app.run("0.0.0.0", 8080)
