from flask import Flask, render_template, request, redirect, url_for, session
import re
import boto3
import botocore.exceptions
import hmac
import hashlib
import base64


USER_POOL_ID = 'your USER_POOL_ID'
CLIENT_ID = 'your CLIENT_ID'
CLIENT_SECRET ='your CLIENT_SECRET'
ACCESS_ID='your ACCESS_ID'
ACCESS_KEY='your ACCESS_KEY'


app = Flask(__name__)


app.secret_key = '1a2b3c4d5e'

@app.route('/login/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        try:
            client = boto3.client('cognito-idp', region_name='us-west-2', aws_access_key_id=ACCESS_ID,aws_secret_access_key= ACCESS_KEY)
            resp,msg = initiate_auth(client, username, password)
            if resp.get("AuthenticationResult"):
                session['loggedin'] = True
                token = resp["AuthenticationResult"]["AccessToken"]
                session['id']=token
                session['username'] = username
                msg='Login successfully'
                return redirect(url_for('home'))
        except client.exceptions.NotAuthorizedException:
             msg = "The username or password is incorrect"
        except client.exceptions.UserNotConfirmedException:
             msg= "User is not confirmed"
        except Exception as e:
             msg = e
        
    return render_template('index.html', msg=msg)


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:        
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$', password):
            msg = 'Password should have Caps, Special characters, Numbers and length of 8'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            try:
                client = boto3.client('cognito-idp', region_name='us-west-2')
                response = client.sign_up(
                        ClientId=CLIENT_ID,
                        SecretHash=get_secret_hash(username),
                        Username=username,
                        Password=password,
                        UserAttributes=[
                                {
                                        'Name': "name",
                                        'Value': username
                                },
                                {
                                        'Name': "email",
                                        'Value': email
                                }
                                        ],
                        ValidationData=[
                                {
                                        'Name': "email",
                                        'Value': email
                                 },
                                 {
                                         'Name': "custom:username",
                                         'Value': username
                                 }
                                ],
                AnalyticsMetadata={ 'AnalyticsEndpointId': 'string'},
                UserContextData={ 'EncodedData': 'string'},
                ClientMetadata={'string': 'string' }
                )
                msg = 'You have successfully registered!'
                return redirect(url_for('ConfirmReg'))
            except client.exceptions.UsernameExistsException as e:
                msg = 'This username already exists'
            except Exception as e:
                msg = e
                
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)

@app.route("/ConfirmReg", methods=["GET", "POST"])
def ConfirmReg():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'code' in request.form:
        username = request.form["username"]
        password = request.form["password"]
        code = request.form["code"]
        if not re.match(r'[A-Za-z0-9]+', code):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        else:
            try:
                client = boto3.client('cognito-idp', region_name='us-west-2')
                response = client.confirm_sign_up(
                 ClientId=CLIENT_ID,
                 SecretHash=get_secret_hash(username),
                 Username=username,
                 ConfirmationCode=code,
                 ForceAliasCreation=False,
                 ) 
                return redirect(url_for("login"))
            except client.exceptions.CodeMismatchException:
                msg = 'Invalid Verification code'
            except client.exceptions.UserNotFoundException:
                msg= 'Username doesnt exists'
            except client.exceptions.NotAuthorizedException:
                msg = 'User is already confirmed'
            except Exception as e:
                msg = e
                
            
    return render_template("ConfirmReg.html",msg=msg)
    


def initiate_auth(client, uname, passw):
    secret_hash = get_secret_hash(uname)
    resp = client.initiate_auth(
    ClientId=CLIENT_ID,
    AuthFlow='USER_PASSWORD_AUTH',
    AuthParameters={
     'USERNAME': uname,
     'SECRET_HASH': secret_hash,
     'PASSWORD': passw
     },
    ClientMetadata={
       'username': uname,
       'password': passw
      })
    return resp,None

def get_secret_hash(username):
    username = request.form["username"]
    msg = username + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'), 
        msg = str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2



@app.route('/home')
def home():
    if 'loggedin' in session:
        return render_template('home.html',username=session['username'],token=session['id'])
    return redirect(url_for('login'))    





if __name__ == '__main__':
    app.run(host='127.0.0.1',debug= True)
