from flask import Flask, render_template, request, redirect, url_for, session
from authlib.integrations.flask_client import OAuth

app = Flask(__name__, template_folder='template')
app.secret_key = "login"

app.config['SERVER_NAME'] = 'localhost:5000'
oauth = OAuth(app)

@app.route('/')
def sss():
    return render_template('message.html')

@app.route("/login", methods=["GET"])
def login():
    if request.method =="GET":
        uname = request.args.get("username")
        password = request.args.get("password")
        if  (uname == "urvashi" and password == "1234"):
            session['email']=uname
            return render_template('message.html', email=uname)
        else:
            error = "invalid username / password"
            return render_template('form.html', error=error)
    else:
        if "email" in session:
            return redirect(url_for("username"))

    return redirect(url_for("sss"))
@app.route('/facebook/')
def facebook():
    oauth.register(
        name='facebook',
        client_id='617030190136856',
        client_secret='7e41f678aeaa8bf13d0d3965243e39f6',
        access_token_url='https://graph.facebook.com/oauth/access_token',
        access_token_params=None,
        authorize_url='https://www.facebook.com/dialog/oauth',
        authorize_params=None,
        api_base_url='https://graph.facebook.com/',
        client_kwargs={'scope': 'email'}
    )
    redirect_uri = url_for('facebook_auth', _external=True)
    return oauth.facebook.authorize_redirect(redirect_uri)

@app.route('/facebook/auth/')
def facebook_auth():
    token = oauth.facebook.authorize_access_token()
    resp = oauth.facebook.get('https://graph.facebook.com/me?fields=id,name,email,picture{url}')
    profile = resp.json()
    print("Facebook User ", profile)
    return render_template('message.html')

@app.route('/google/')
def google():
    CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    oauth.register(
        name='google',
        client_id='763324364038-qfa6a5r0sr6tg6m67le4ikgsqprguasr.apps.googleusercontent.com',
        client_secret='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',
        server_metadata_url=CONF_URL,
        client_kwargs={ 'scope': 'openid email profile' }
    )

    # Redirect to google_auth function
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/google/auth/')
def google_auth():
    token = oauth.google.authorize_access_token()
    user = oauth.google.parse_id_token(token, None)
    print(" Google User ", user)
    return render_template('message.html')

@app.route('/logout')
def logout():
    session.pop('email', None)
    return render_template('form.html')


if __name__=="__main__":
    app.run(debug=True)
