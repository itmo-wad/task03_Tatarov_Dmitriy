from flask import Flask, request, redirect, url_for, render_template, flash, jsonify, make_response
from . models import User, db
from . forms import  SignUpForm, SignInForm
from main import app
import hashlib
import json
import bcrypt
import hmac
import glob, os

db.create_all()
key=b'super_secret_k3y_y0u_will_n3v3r_gue$$'
def session_new(username):
    hmac_val = hmac.new(key, username.encode(), 'sha256').hexdigest()
    f_name = "sessions/"+hmac_val+".json"
    data={"username":username,"hmac":hmac_val}
    with open(f_name, 'w') as fp: 
        json.dump(data, fp)
    return data

def session_check(cookie):
    cookie = json.loads(cookie)
    fname = "sessions/"+cookie["hmac"]+".json"
    if glob.glob(fname):
        with open(fname) as fp: 
            data = json.load(fp)
        if data["username"]==cookie["username"] and cookie["hmac"]==data["hmac"]:
            return True
        else:
            return False

def session_delete(cookie):
    cookie = json.loads(cookie)
    fname="sessions/"+cookie["hmac"]+".json"
    if glob.glob(fname):
        os.remove(fname)

@app.route('/')
def index():  
    if 'login' in request.cookies:
        if session_check(request.cookies["login"]):
            return redirect(url_for('secret'))
    flash('You are not authenticated')
    return redirect(url_for('signin'))


@app.route('/secret', methods=['GET'])
def secret():
    if 'login' in request.cookies:
        if session_check(request.cookies["login"]):
            return render_template('secret.html',username=str(json.loads(request.cookies["login"])["username"]))
    flash('You are not authenticated')
    return redirect(url_for('signin'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'login' in request.cookies:
        if session_check(request.cookies["login"]):
            return redirect(url_for('secret'))
    signupform = SignUpForm(request.form)
    if request.method == 'POST' and signupform.validate_on_submit():
        try:
            salt = bcrypt.gensalt()
            password = bcrypt.hashpw((signupform.password.data).encode('utf-8'), salt)
            reg = User(signupform.username.data, password, salt)
            db.session.add(reg)
            db.session.commit()
        except Exception as e:
            flash("Something wrong")
            print(e)
            return render_template('signup.html', signupform=signupform)
        return redirect(url_for('signin'))
    return render_template('signup.html', signupform=signupform)


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if 'login' in request.cookies:
        if session_check(request.cookies["login"]):
            return redirect(url_for('secret'))
    signinform = SignInForm(request.form)
    if request.method == 'POST':
        if signinform.validate_on_submit():
            username = signinform.username.data
            log = User.query.filter_by(username=username).first()
            if log!=None:
                if log.password == bcrypt.hashpw((signinform.password.data).encode('utf-8'), log.salt):
                    current_user = log.username
                    cookie = session_new(current_user)
                    response = make_response(redirect(url_for('secret')))
                    response.set_cookie('login', json.dumps(cookie),httponly = True)
                    return response
                else:
                    flash('Wrong login or password') 
            else:
                flash('Wrong login or password')
    return render_template('signin.html', signinform=signinform)


@app.route('/logout')
def logout():
    if 'login' in request.cookies:
        session_delete(request.cookies["login"])
    response = make_response(redirect(url_for('signin')))
    response.set_cookie("login", '', expires=0)
    return response

if __name__ == '__main__':
    app.run()
