from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc, desc, func
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

# stores a session id to block 3rd party from saying they are the user
# things only work on this session id
from flask import session as login_session
import random, string

# json for storing client id, client secret, etc
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


#Connect to Database and create database session
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create a state token to prevent request forgery.
# Store it in the session for later validation.
@app.route('/login/')
def showLogin():
  state = ''.join(random.choice(string.ascii_uppercase + string.digits) 
                  for x in xrange(32))
  login_session['state'] = state
  return render_template('login.html', STATE=state, session = login_session, hide_categories=True)


# Google connect/disconnect

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"

@app.route('/gconnect', methods=['POST'])
def gconnect():
  # Check that it is the user, not a script, making the request (validate state)
  if request.args.get('state') != login_session['state']:
    response = make_response(json.dumps('Invalid state parameter'), 401)
    response.headers['Content-type'] = 'application/json'
    return response

  # get the one time code and try to exchange it for an acces token
  code = request.data
  try:
    # Upgrade the authorization code into a credentials object (token)
    oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
    oauth_flow.redirect_uri = 'postmessage'
    credentials = oauth_flow.step2_exchange(code)
  except FlowExchangeError:
    response = make_response(json.dumps("Failed to upgrade the authorization code."), 401)
    response.headers['Content-type'] = 'application/json'
    return response

  # Check that access token is valid
  access_token = credentials.access_token
  url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
  h = httplib2.Http()
  result = json.loads(h.request(url, 'GET')[1])
  # If there was an error in the access token info, abort
  if result.get('error') is not None:
    response = make_response(json.dumps(result.get('error')), 500)
    response_headers['Content-type'] = 'application/json'
    return response

  # Verify that the access token is used for the intended user.
  gplus_id = credentials.id_token['sub']
  if result['user_id'] != gplus_id:
    response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
    response.headers['Content-type'] = 'application/json'
    return response

  # Verify that the acces token is valid for this app.
  if result['issued_to'] != CLIENT_ID:
    response = make_response(json.dumps("Token's client ID does not match app's"), 401)
    print "Token's client ID doesn not match app's."
    response.headers['Content-type'] = 'application/json'
    return response

  # Verify to see if user is already logged in
  stored_access_token = login_session.get('access_token')
  stored_gplus_id = login_session.get('gplus_id')
  if stored_access_token is not None and gplus_id == stored_gplus_id:
    response = make_response(json.dumps('Current user is already connected.'), 200)
    response.headers['Content-type'] = 'application/json'
    return response

  # Store the access token in the session for later use
  login_session['access_token'] = credentials.access_token
  login_session['gplus_id'] = gplus_id

  # Get user info
  userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
  params = {'access_token': credentials.access_token, 'alt':'json'}
  answer = requests.get(userinfo_url, params=params)

  data = answer.json()

  login_session['username'] = data["name"]
  login_session['picture'] = data["picture"]
  login_session['email'] = data["email"]

  # Check if the user is in the local database
  user_id = getUserID(login_session['email'])
  if not user_id:
    user_id = createUser(login_session)
  login_session['user_id'] = user_id


  output  = "<h1>Welcome, " + login_session['username'] + "!</h1>"
  output += '<img src="' + login_session['picture'] + """
" style="width: 300px; height: 300px; border-radius:150px; 
-webkit-border-radius: 150px; -moz-border-radius: 150px;"> """

  flash("You are now logged in as " + login_session['username'])
  return output

# DISCONNECT - Revoke a current user's toke and reset their login_session
@app.route("/gdisconnect")
@app.route("/logout")
def gdisconnect():
  # Only disconnect a connected user.
  access_token = login_session.get('access_token')
  if access_token is None:
    response = make_response(json.dumps("Current user not connected."), 401)
    response.headers['Content-type'] = 'application/json'
    return response
  
  # Execute HTTP GET request to revoke current token.
  url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
  print url
  h = httplib2.Http()
  result = h.request(url, "GET")[0]
  print 'result is '
  print result

  # If there was a problem, probably the token is expired and 
  # the user needs to be deleted from the session
  if result['status'] == '200' or True:
    del login_session['access_token']
    del login_session['gplus_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    # response = make_response(json.dumps("Successfully disconnected."), 200)
    # response.headers['Content-type'] = 'application/json'

    flash("You have successfully been logged out.")
    return redirect(url_for('showCatalog'))


  else:  # Not applicable anymore
    # For whatever reason, the given token was invalid.
    response = make_response("Failed to revoke token for given user.", 400)
    response.headers['Content-type'] = 'application/json'
    return response


# CRUD

@app.route('/catalog.json')
def showCatalogJSON():
    categories = session.query(Category).order_by(asc(Category.name))    
    serializedCategories = []

    for category in categories:
        cat = category.serialize
        items = session.query(Item).filter(Item.category.has(name=category.name)).all()
        serializedItems = []
        for item in items:
            serializedItems.append(item.serialize)
        cat['items'] = serializedItems
        serializedCategories.append(cat)

    return jsonify(categories = [serializedCategories])


# User utilities

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/')
@app.route('/catalog')
def showCatalog():
    categories = session.query(Category).order_by(asc(Category.name))
    lastItems = session.query(Item).order_by(desc(Item.created)).limit(10)
    print session.query(func.count(Item.id)).one()
    return render_template('front.html', categories = categories, items=lastItems,
     session=login_session)

@app.route('/catalog/<string:category_name>/')
def showCategory(category_name):
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Item).filter(Item.category.has(name=category_name)).all()
    return render_template('category.html', items=items, categories=categories, 
        category_name=category_name, session = login_session)

@app.route('/catalog/<string:category_name>/<string:item_name>')
def showItem(category_name, item_name):
    categories = session.query(Category).order_by(asc(Category.name))
    item = session.query(Item).filter(Item.category.has(name=category_name)).filter_by(name = item_name).one()
    # Check if the user is allowed to edit/delete the item
    if 'username' not in login_session or login_session['user_id'] != item.user_id:
        return render_template('item_public.html', item=item, categories=categories, 
            session=login_session)
    else:
        return render_template('item.html', item=item, categories=categories, 
            session=login_session)


@app.route('/catalog/<string:category_name>/new/', methods=['GET', 'POST'])
def newItem(category_name):
    # Check if user is logged in
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category = session.query(Category).filter_by(name=category_name).one()
        newItem = Item(name=request.form['name'], description=request.form['description'], 
            category_id=category.id, user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Item %s Successfully Created' % (newItem.name))
        return redirect(url_for('showCategory', category_name = category_name))
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('newitem.html', categories=categories, 
            category_name=category_name, session = login_session)


@app.route('/catalog/<string:item_name>/edit', methods=['GET', 'POST'])
def editItem(item_name):
    # Check if user is logged in
    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(Item).filter_by(name=item_name).one()
    # Check if he is allowed to edit
    if login_session['user_id'] != item.user_id:
        return """<script>function myFunction() {alert('You are not authorized to edit this item. 
            You can only edit items created by yourself.');}</script><body onload='myFunction()''>"""
    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        session.add(item)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showCategory', category_name = item.category.name))
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('edititem.html', categories = categories, item=item, 
            session = login_session)


@app.route('/catalog/<string:item_name>/delete', methods=['GET', 'POST'])
def deleteItem(item_name):
    # Check if user is logged in
    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(Item).filter_by(name=item_name).one()
    # Check if he is allowed to edit
    if login_session['user_id'] != item.user_id:
        return """<script>function myFunction() {alert('You are not authorized to delete this item. 
            You can only delete items created by yourself.');}</script><body onload='myFunction()''>"""
    if request.method == 'POST':
        # Storing the category name before deleting it
        category_name = item.category.name
        session.delete(item)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showCategory', category_name = category_name))
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('deleteitem.html', item=item, categories = categories, 
            session = login_session)

if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 8000)
