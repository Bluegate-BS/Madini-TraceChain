########################################################################################
######################          Import packages      ###################################
########################################################################################
from flask import Blueprint,Flask, render_template, redirect, url_for, request, flash ,  jsonify 
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from models import Verif
from flask import send_from_directory
from flask_login import login_user, logout_user, login_required, current_user
from __init__ import db
import json
from thor_devkit import cry, transaction
from random import randint
import requests
from flask_qrcode import QRcode
import requests
from random import randint
from werkzeug.utils import secure_filename
import imghdr
import os
from flask_sqlalchemy import SQLAlchemy
import sqlite3
from sqlalchemy import create_engine
import datetime;
import glob
from uuid import uuid4
from flask import current_app
from sqlalchemy import desc
from logging import Formatter, FileHandler
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
auth = Blueprint('auth', __name__) # create a Blueprint object that we name 'auth'
path = os.getcwd()
# file Upload
node='https://mainnet.veblocks.net'
explore='https://explore.vechain.org/transactions/'
chaintag= 74

from logging import Formatter, FileHandler
handler = FileHandler(os.path.join(basedir, 'log.txt'), encoding='utf8')
handler.setFormatter(
    Formatter("[%(asctime)s] %(levelname)-8s %(message)s", "%Y-%m-%d %H:%M:%S")
)
app.logger.addHandler(handler)

app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)

def dated_url_for(endpoint, **values):
    if endpoint == 'js_static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path,
                                     'static/js', filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    elif endpoint == 'css_static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path,
                                     'static/css', filename)
            values['q'] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)

@auth.route('/js/<path:filename>')
def js_static(filename):
    return send_from_directory(app.root_path + '/static/js/', filename)

@auth.route('/login', methods=['GET', 'POST']) 
def login():
    if request.method=='GET': 
        return render_template('login.html')
    else: 
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Please sign up before!')
            return redirect(url_for('auth.signup'))
        elif not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login')) 
        login_user(user, remember=remember)
        return redirect(url_for('main.profile'))
 
@auth.route('/createnew', methods=['GET', 'POST'])
def CreatenewRouted():
    if request.method == "POST":
            username = str(request.json['username'])
            des = str(request.json['des'])
            sku = str(request.json['sku'])
            pname = str(request.json['pname'])
            ptype = str(request.json['type'])
            mainimage = str(request.json['mainimage'])
            shape = str(request.json['shape'])
            color = str(request.json['color'])
            carats = str(request.json['carats'])
            cut = str(request.json['cut'])
            category = str(request.json['category'])
            clarity = str(request.json['clarity'])
            _node_url = node
            BlockInfos = requests.get(_node_url + '/blocks/best')	
            _BlockRef = BlockInfos.json()['id'][0:18]
            _Nonce = randint(10000000, 99999999)
            delegated_body = {
                "chainTag": chaintag,
                "blockRef": _BlockRef,
                "expiration": 720,
                "clauses": [
                    {
                        "to": '',#enter to address
                        "value": 0,
                        "data": '0x' +username
                    }
                ],
                "gasPriceCoef": 0,
                "gas": 100000,
                "dependsOn": None,
                "nonce": _Nonce,
                "reserved": {
                    "features": 1
                }
            }
            print(username)
            delegated_tx = transaction.Transaction(delegated_body)
            assert delegated_tx.is_delegated() == True
            # Sender address
            addr_1 = ''
            priv_1 = bytes.fromhex('') # Sender private key address
            # Gas 5
            addr_2 = '' # Gas Payer
            priv_2 = bytes.fromhex('')#Gas payer key
            h = delegated_tx.get_signing_hash() # Sender hash to be signed.
            dh = delegated_tx.get_signing_hash(addr_1) # Gas Payer hash to be signed.
            # Sender sign the hash.
            # Gas payer sign the hash.
            # Concat two parts to forge a legal signature.
            sig = cry.secp256k1.sign(h, priv_1) + cry.secp256k1.sign(dh, priv_2)
            delegated_tx.set_signature(sig)
            encoded_bytes = delegated_tx.encode()
            tx_data = {'raw': '0x' + encoded_bytes.hex()}
            print(tx_data)
            ts = datetime.datetime.now()
            tx_headers = {'Content-Type': 'application/json', 'accept': 'application/json'}
            send_transaction = requests.post(_node_url + '/transactions', json=tx_data, headers=tx_headers)
            print('Response from Server: ' + str(send_transaction.content))
            prt=str(send_transaction.content)
            encoded_bytes = delegated_tx.encode()
            new_verif = Verif(bhash=des, mid=username, thash=delegated_tx.get_id(), sku=sku, pname=pname ,mainimage=mainimage ,datetime=ts,ptype=ptype,shape=shape,color=color,carats=carats,clarity=clarity,cut=cut,category=category) #
            db.session.add(new_verif)
            db.session.commit()
            return "<a target='blank' href='https://explore.vechain.org/transactions/"+delegated_tx.get_id()+"'>Explorer</a>"

@auth.route('/verified', methods=['GET','POST'])
def delete():
    thash = request.args.get('thash')
    pname = request.args.get('pname')
    sku = request.args.get('sku')
    mainimage = request.args.get('mainimage')
    bhash = request.args.get('bhash')
    imageone = request.args.get('imageone')
    imagetwo = request.args.get('imagetwo')
    imagethree = request.args.get('imagethree')
    imagefour = request.args.get('imagefour')
    imagefive = request.args.get('imagefive')
    fileone = request.args.get('fileone')
    filetwo = request.args.get('filetwo')
    filethree = request.args.get('filethree')
    porigin = request.args.get('porigin')
    lat = request.args.get('lat')
    longt = request.args.get('longt')
    id = request.args.get('id')
    return render_template('view.html',thash=thash,pname=pname,sku=sku,mainimage=mainimage,bhash=bhash,imageone=imageone,id=id, imagetwo=imagetwo, imagethree=imagethree, imagefour=imagefour, imagefive=imagefive, fileone=fileone, filetwo=filetwo, filethree=filethree ,porigin=porigin, longt=longt ,lat=lat)
@auth.route('/profile')
def show_all():
        total= Verif.query.count()

        return render_template('profile.html', value=total)           

@auth.route('/signup', methods=['GET', 'POST'])
def signup(): 
    if request.method=='GET':
        return render_template('signup.html')
    else: 
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first() 
        if user:
            flash('Email address already exists')
            return redirect(url_for('auth.signup'))
        new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256')) #
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout(): 
    logout_user()
    return redirect(url_for('main.index'))



@auth.route('/projects')
def projects():
            return render_template('showprojects.html', verif = Verif.query.order_by(Verif.id.desc()).all()) 
@auth.route('/new')
def new():
            return render_template('new.html', verif = Verif.query.order_by(Verif.id.desc()).all())            
