from flask import Flask, request, jsonify
from flask_restful import Api
import json
import eth_account
import algosdk


#In this assignment, you will use Python-Flask to create a REST endpoint that takes 
# a (JSON) object and a signature, and verifies that the signatures is valid. 
# Your endpoint should accept both signatures generated from Ethereum and Algorand keys.

app = Flask(__name__)
api = Api(app)
app.url_map.strict_slashes = False

#Your REST endpoint should provide a single route “/verify” which should process a “GET” request. 
# The request should contain a JSON object with two fields “payload” and “signature.” 
# The “payload” portion should have (at least) three fields “platform” and “pk” and "message".

    #c = [
    #{'sig': '0x3718eb506f445ecd1d6921532c30af84e89f2faefb17fc8117b75c4570134b4967a0ae85772a8d7e73217a32306016845625927835818d395f0f65d25716356c1c', 
    #'payload': 
    #{'message': 'Ethereum test message', 
    #    'pk': '0x9d012d5a7168851Dc995cAC0dd810f201E1Ca8AF', 
    #    'platform': 'Ethereum'}}
    #]

#The platform should be either “Ethereum” or “Algorand” (which will tell your script 
# which type of verification algorithm to use). The “sig” field should contain a 
# valid signature on the JSONified dictionary “payload” (e.g. by calling json.dumps).

# The signature should be on the entire payload dictionary not just the single “message” field.

#The endpoint should return “True” if the signature verifies and “False” otherwise. 
# The response should be appropriately jsonified using the jsonify(response)
#Your script should be called “verification_endpoint.py” and a skeleton file is provided.


@app.route('/verify', methods=['GET','POST'])
def verify():
    content = request.get_json(silent=True)

    if 'platform' in json.dumps(content):
        platform = int(request.args['platform'])

    if platform="Ethereum":
        eth_account.Account.enable_unaudited_hdwallet_features()
        acct, mnemonic = eth_account.Account.create_with_mnemonic()
        eth_pk = acct.address
        eth_sk = acct.key
        payload = "Sign this!"
        eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)
        #The variable eth_sig_obj.signature is of type HexBytes which is not JSON serializable
        eth_sig_obj = eth_account.Account.sign_message(eth_encoded_msg,eth_sk)
        print( eth_sig_obj.messageHash )
        #recover_message will return the signer’s public key if and only if the signature verifies
        # "eth_sig_obj.signature.hex()" and  “eth_sig_obj.signature” return the same message, 
        # but the latter cannot be converted to a JSON string.
        if eth_account.Account.recover_message(eth_encoded_msg,signature=eth_sig_obj.signature.hex()) == eth_pk:
            print( "Eth sig verifies!" )

    if platform="Algorand":
        payload = "Sign this!"
        algo_sk, algo_pk = algosdk.account.generate_account()
        algo_sig_str = algosdk.util.sign_bytes(payload.encode('utf-8'),algo_sk)
        if algosdk.util.verify_bytes(payload.encode('utf-8'),algo_sig_str,algo_pk):
            print( "Algo sig verifies!" )
        

    #Check if signature is valid
    result = True #Should only be true if signature validates
    return jsonify(result)

if __name__ == '__main__':
    app.run(port='5002')
