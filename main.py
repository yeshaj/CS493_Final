# References:
# https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator
# Exploration - Authentication in Python
# Multiple articles on community.auth0.com
# https://stackoverflow.com/questions/50182833/google-cloud-app-engine-502-bad-gateway-nginx-error-with-flask-app

from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack, make_response
import requests

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt


import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode


app = Flask(__name__)
app.secret_key = b'ayj97b10'

client = datastore.Client()

BOATS = "boats"
LOADS = "loads"
USERS = "users"

CLIENT_ID = 'DFYvbGs5Mr1QUCUIO8SBhYRTi5YU3W9q'
CLIENT_SECRET = 'lwe_sHvrNbLv63HTP8i9i2tEqQuGwfXTQ-NwCNn8wmydBr6MDpAoIpc14FGIjTav'
DOMAIN = 'jhalay-493-final.us.auth0.com'

CALLBACK_URL = 'https://final-project-jhalay.uw.r.appspot.com/callback'

ALGORITHMS = ["RS256"]


oauth = OAuth(app)

auth0 = oauth.register(
   'auth0',
   client_id=CLIENT_ID,
   client_secret=CLIENT_SECRET,
   api_base_url="https://" + DOMAIN,
   access_token_url="https://" + DOMAIN + "/oauth/token",
   authorize_url="https://" + DOMAIN + "/authorize",
   client_kwargs={
      'scope': 'openid profile email',
   },
)

class AuthError(Exception):
   def __init__(self, error, status_code):
      self.error = error
      self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
   response = jsonify(ex.error)
   response.status_code = ex.status_code
   return response

def verify_jwt(request):
   auth_header = request.headers['Authorization'].split();
   token = auth_header[1]

   jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
   jwks = json.loads(jsonurl.read())
   try:
      unverified_header = jwt.get_unverified_header(token)
   except jwt.JWTError:
      raise AuthError({"code": "invalid_header",
                     "description":
                           "Invalid header. "
                           "Use an RS256 signed JWT Access Token"}, 401)
   if unverified_header["alg"] == "HS256":
      raise AuthError({"code": "invalid_header",
                     "description":
                           "Invalid header. "
                           "Use an RS256 signed JWT Access Token"}, 401)
   rsa_key = {}
   for key in jwks["keys"]:
      if key["kid"] == unverified_header["kid"]:
         rsa_key = {
               "kty": key["kty"],
               "kid": key["kid"],
               "use": key["use"],
               "n": key["n"],
               "e": key["e"]
         }
   if rsa_key:
      try:
         payload = jwt.decode(
               token,
               rsa_key,
               algorithms=ALGORITHMS,
               audience=CLIENT_ID,
               issuer="https://"+ DOMAIN+"/"
         )
      except jwt.ExpiredSignatureError:
         raise AuthError({"code": "token_expired",
                           "description": "token is expired"}, 401)
      except jwt.JWTClaimsError:
         raise AuthError({"code": "invalid_claims",
                           "description":
                              "incorrect claims,"
                              " please check the audience and issuer"}, 401)
      except Exception:
         raise AuthError({"code": "invalid_header",
                           "description":
                              "Unable to parse authentication"
                              " token."}, 401)

      return payload
   else:
      raise AuthError({"code": "no_rsa_key",
                           "description":
                              "No RSA key in JWKS"}, 401)

def requires_auth(f):
   @wraps(f)
   def decorated(*args, **kwargs):
      if 'profile' not in session:
         return redirect('/')
      return f(*args, **kwargs)
   return decorated


################# API Routes Below Here ###########################

################# User Routes #####################################

@app.route('/users', methods=['GET', 'DELETE', 'PUT', 'PATCH', 'POST'])
def users_get():
   if request.method == 'GET':
      if 'application/json' in request.accept_mimetypes:
         try:
            query = client.query(kind=USERS)
            results = list(query.fetch())
            response = []
            for user in results:
               response.append(user_response(user, False))
            result = header_result(jsonify(response), 'application/json', 200)
            return (result)
         except Exception as error:
            response = error_response(str(error))
            result = header_result(response, 'application/json', 400)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'DELETE':
      response = error_response("Method not allowed. Allowed methods for /users/ are: GET")
      result = header_result(response, 'application/json', 405)
      return (result)
   elif request.method == 'PUT':
      response = error_response("Method not allowed. Allowed methods for /users/ are: GET")
      result = header_result(response, 'application/json', 405)
      return (result)
   elif request.method == 'PATCH':
      response = error_response("Method not allowed. Allowed methods for /users/ are: GET")
      result = header_result(response, 'application/json', 405)
      return (result)
   elif request.method == 'POST':
      response = error_response("Method not allowed. Allowed methods for /users are: GET")
      result = header_result(response, 'application/json', 405)
      return (result)
   else:
      return 'Method not recognized'


################# Boat Routes #####################################

@app.route('/boats', methods=['GET','POST', 'PUT', 'PATCH', 'DELETE'])
def boats_get_post():
   if request.method == 'GET':
      if 'application/json' in request.accept_mimetypes:
         try:
            payload = verify_jwt(request)
            owner = payload['sub']
            query = client.query(kind=BOATS)
            query.add_filter('owner', '=', owner)
            collection = list(query.fetch())
            collection_size = len(collection)
            limit = int(request.args.get('limit', '5'))
            offset = int(request.args.get('offset', '0'))
            iterator = query.fetch(limit= limit, offset=offset)
            pages = iterator.pages
            boat_page = list(next(pages))
            if iterator.next_page_token:
               next_offset = offset + limit
               next_url = request.base_url + "?limit=" + str(limit) + "&offset=" + str(next_offset)
            else:
               next_url = None
            for boat in boat_page:
               boat['id'] = boat.key.id
               boat['self'] = "https://" + request.host + '/boats/' + str(boat.key.id)
               loads = boat['loads']
               for load in loads:
                  load['self'] = "https://" + request.host + '/loads/' + str(load['id'])
            output = {"Boats": boat_page}
            if next_url:
               output["next_page"] = next_url
            output['collection_size'] = collection_size
            result = header_result(jsonify(output), 'application/json', 200)
            return (result)
         except Exception:
            response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
            result = header_result(response, 'application/json', 401)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'POST':
      if 'application/json' in request.accept_mimetypes:
         if 'application/json' in request.content_type:
            try:
               payload = verify_jwt(request)
               owner = payload['sub']
               content = request.get_json()
               new_boat = datastore.entity.Entity(key=client.key(BOATS))
               new_boat.update({"name": content["name"], "type": content["type"],
                  "length": content["length"], "owner": owner, "loads": []})
               client.put(new_boat)
               response = boat_response(new_boat, True)
               result = header_result(response, 'application/json', 201)
               return (result)
            except KeyError:
               response = error_response("The boat is missing at least one of the required attributes, or the HTTP Header is missing an authorization token")
               return (response, 400)
            except Exception:
               response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
               result = header_result(response, 'application/json', 401)
               return (result)
         else:
            response = error_response("User sent an unsupported media type. Supported media types are: application/json")
            result = header_result(response, 'application/json', 415)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'PUT':
      response = error_response("Method not allowed. Allowed methods for /boats are: GET, POST")
      result = header_result(response, 'application/json', 405)
      return (result)
   elif request.method == 'PATCH':
      response = error_response("Method not allowed. Allowed methods for /boats are: GET, POST")
      result = header_result(response, 'application/json', 405)
      return (result)
   elif request.method == 'DELETE':
      response = error_response("Method not allowed. Allowed methods for /boats are: GET, POST")
      result = header_result(response, 'application/json', 405)
      return (result)
   else:
      return 'Method not recognized'


# Delete a specific boat
@app.route('/boats/<boat_id>', methods=['DELETE','GET','PUT','PATCH', 'POST'])
def boat_delete_get_put_patch(boat_id):
   if request.method == 'DELETE':
      if 'application/json' in request.accept_mimetypes:
         try:
            payload = verify_jwt(request)
            owner = payload['sub']
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)
            boat.get('id')
            if boat['owner'] != owner:
               response = error_response("Not authorized to delete boat with this id")
               result = header_result(response, 'application/json', 403)
               return (result)
            query = client.query(kind=LOADS)
            loads_list = list(query.fetch())
            for load in loads_list:
               load_carrier = load['carrier']
               for carrier in load_carrier:
                  if carrier.id == boat.get('id'):
                     load['carrier'] = []
                     client.put(load)
            client.delete(boat_key)
            result = header_result('', 'application/json', 204)
            return (result)
         except AttributeError:
            response = error_response('No boat with this boat_id exists')
            result = header_result(response, 'application/json', 403)
            return (result)
         except Exception:
            response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
            result = header_result(response, 'application/json', 401)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'GET':
      if 'application/json' in request.accept_mimetypes:
         try:
            payload = verify_jwt(request)
            owner = payload['sub']
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)
            boat.get('id')
            if boat['owner'] != owner:
               response = error_response("Not authorized to view boat with this id")
               result = header_result(response, 'application/json', 403)
               return (result)
            response = boat_response(boat, False)
            loads = response['loads']
            for load in loads:
               load['self'] = "https://" + request.host + '/loads/' + str(load['id'])
            result = header_result(response, 'application/json', 200)
            return (result)
         except AttributeError:
            response = error_response('No boat with this boat_id exists')
            result = header_result(response, 'application/json', 403)
            return (result)
         except Exception:
            response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
            result = header_result(response, 'application/json', 401)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'PUT':
      if 'application/json' in request.accept_mimetypes:
         if 'application/json' in request.content_type:
            try:
               payload = verify_jwt(request)
               owner = payload['sub']
               content = request.get_json()
               boat_key = client.key(BOATS, int(boat_id))
               boat = client.get(key=boat_key)
               boat.get('id')
               if boat['owner'] != owner:
                  response = error_response("Not authorized to edit boat with this id")
                  result = header_result(response, 'application/json', 403)
                  return (result)
               boat.update({"name": content["name"], "type": content["type"], "length": content["length"]})
               client.put(boat)
               response = boat_response(boat, False)
               result = header_result(response, 'application/json', 200)
               return (result)
            except KeyError:
               response = error_response("The boat is missing at least one of the required attributes, or the HTTP Header is missing an authorization token")
               result = header_result(response, 'application/json', 400)
               return (result)
            except AttributeError:
               response = error_response('No boat with this boat_id exists')
               result = header_result(response, 'application/json', 403)
               return (result)
            except Exception:
               response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
               result = header_result(response, 'application/json', 401)
               return (result)
         else:
            response = error_response("User sent an unsupported media type. Supported media types are: application/json")
            result = header_result(response, 'application/json', 415)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'PATCH':
      if 'application/json' in request.accept_mimetypes:
         if 'application/json' in request.content_type:
            try:
               payload = verify_jwt(request)
               owner = payload['sub']
               content = request.get_json()
               boat_key = client.key(BOATS, int(boat_id))
               boat = client.get(key=boat_key)
               boat.get('id')
               if boat['owner'] != owner:
                  response = error_response("Not authorized to view boat with this id")
                  result = header_result(response, 'application/json', 403)
                  return (result)
               query = client.query(kind=BOATS)
               boats_list = list(query.fetch())
               for key, value in content.items():
                  if key == 'type':
                     boat.update({key: content[key]})
                  elif key == 'length':
                     boat.update({key: content[key]})
                  elif key == 'name':
                     boat.update({key: content[key]})
                  else:
                     response = error_response("The boat is missing at least one of the required attributes.")
                     result = header_result(response, 'application/json', 400)
                     return (result)
               client.put(boat)
               response = boat_response(boat, False)
               result = header_result(response, 'application/json', 200)
               return (result)
            except KeyError:
               response = error_response("The boat is missing at least one of the required attributes, or the HTTP Header is missing an authorization token")
               result = header_result(response, 'application/json', 400)
               return (result)
            except AttributeError:
               response = error_response('No boat with this boat_id exists')
               result = header_result(response, 'application/json', 403)
               return (result)
            except Exception:
               response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
               result = header_result(response, 'application/json', 401)
               return (result)
         else:
            response = error_response("User sent an unsupported media type. Supported media types are: application/json")
            result = header_result(response, 'application/json', 415)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'POST':
      response = error_response("Method not allowed. Allowed methods for /boats/<boat_id> are: PUT, PATCH, DELETE, GET")
      result = header_result(response, 'application/json', 405)
      return (result)
   else:
      return 'Method not recognized'


@app.route('/<boat_id>/loads/<load_id>', methods=['PUT','DELETE', 'PATCH', 'POST', 'GET'])
def boat_add_delete_load(boat_id, load_id):
   if request.method == 'PUT':
      if 'application/json' in request.accept_mimetypes:
         try:
            payload = verify_jwt(request)
            owner = payload['sub']
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)
            load_key = client.key(LOADS, int(load_id))
            load = client.get(key=load_key)
            load.get('id')
            boat.get('id')
            if boat['owner'] != owner:
               response = error_response("Not authorized to edit boat with this id")
               result = header_result(response, 'application/json', 403)
               return (result)
            if 'loads' in boat.keys():
               load_list = boat['loads']
               for item in load_list:
                  if item['id'] == load.key.id:
                     response = error_response("The load with load_id is already assigned to the boat with boat_id")
                     result = header_result(response, 'application/json', 403)
                     return (result)
               boat_load = boat_load_object(load)
               boat['loads'].append(boat_load)
               load_carrier = load_carrier_object(boat)
               load['carrier'].append(load_carrier)
            else:
               boat_load = boat_load_object(load)
               boat['loads'] = boat_load
               load_carrier = load_carrier_object(boat)
               load['carrier'].append(load_carrier)
            client.put(load)
            client.put(boat)
            response = ''
            result = header_result(response, 'application/json', 204)
            return (result)
         except AttributeError:
            response = error_response('The specified boat and/or load does not exist')
            result = header_result(response, 'application/json', 403)
            return (result)
         except Exception:
            response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
            result = header_result(response, 'application/json', 401)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'DELETE':
      if 'application/json' in request.accept_mimetypes:
         try:
            payload = verify_jwt(request)
            owner = payload['sub']
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)
            load_key = client.key(LOADS, int(load_id))
            load = client.get(key=load_key)
            load.get('id')
            boat.get('id')
            load_found = False
            carrier_found = False
            if boat['owner'] != owner:
               response = error_response("Not authorized to edit boat with this id")
               result = header_result(response, 'application/json', 403)
               return (result)
            if 'loads' in boat.keys():
               load_list = boat['loads']
               if load_list == []:
                  response = error_response("The load with load_id does not exist on boat with boat_id")
                  result = header_result(response, 'application/json', 403)
                  return (result)
               for item in load_list:
                  if item['id'] == load.key.id:
                     boat['loads'].remove(item)
                     load_found = True
               carrier_list = load['carrier']
               for carrier in carrier_list:
                  if carrier['id'] == boat.key.id:
                     load['carrier'].remove(carrier)
                     carrier_found = True
               if load_found and carrier_found:
                  client.put(load)
                  client.put(boat)
                  response = ''
                  result = header_result(response, 'application/json', 204)
                  return (result)
               elif not load_found:
                  response = error_response("The load with load_id does not exist on boat with boat_id")
                  result = header_result(response, 'application/json', 403)
                  return (result)
               elif not carrier_found:
                  response = error_response("The load with load_id's carrier isn't is empty or isn't the boat with boat_id")
                  result = header_result(response, 'application/json', 403)
                  return (result)
            else:
               response = error_response("The load with load_id does not exist on boat with boat_id")
               result = header_result(response, 'application/json', 403)
               return (result)
         except AttributeError:
            response = error_response('The specified boat and/or load does not exist')
            result = header_result(response, 'application/json', 403)
            return (result)
         except Exception:
            response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
            result = header_result(response, 'application/json', 401)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'PATCH':
      response = error_response("Method not allowed. Allowed methods for /<boat_id>/loads/<load_id> are: PUT, DELETE")
      result = header_result(response, 'application/json', 405)
      return (result)
   elif request.method == 'POST':
      response = error_response("Method not allowed. Allowed methods for /<boat_id>/loads/<load_id> are: PUT, DELETE")
      result = header_result(response, 'application/json', 405)
      return (result)
   elif request.method == 'GET':
      response = error_response("Method not allowed. Allowed methods for /<boat_id>/loads/<load_id> are: PUT, DELETE")
      result = header_result(response, 'application/json', 405)
      return (result)
   else:
      return 'Method not recognized'

################# Load Routes #####################################

@app.route('/loads', methods=['GET','POST', 'PUT', 'PATCH', 'DELETE'])
def loads_get_post():
   if request.method == 'GET':
      if 'application/json' in request.accept_mimetypes:
         try:
            payload = verify_jwt(request)
            owner = payload['sub']
            query = client.query(kind=LOADS)
            collection = list(query.fetch())
            collection_size = len(collection)
            limit = int(request.args.get('limit', '5'))
            offset = int(request.args.get('offset', '0'))
            iterator = query.fetch(limit= limit, offset=offset)
            pages = iterator.pages
            load_page = list(next(pages))
            if iterator.next_page_token:
               next_offset = offset + limit
               next_url = request.base_url + "?limit=" + str(limit) + "&offset=" + str(next_offset)
            else:
               next_url = None
            for load in load_page:
               load["id"] = load.key.id
               load['self'] = "https://" + request.host + '/loads/' + str(load.key.id)
               carriers = load['carrier']
               for boat in carriers:
                  boat['self'] = "https://" + request.host + '/boats/' + str(boat['id'])
            output = {"Loads": load_page}
            if next_url:
               output["next_page"] = next_url
            output['collection_size'] = collection_size
            result = header_result(jsonify(output), 'application/json', 200)
            return (result)
         except Exception:
            response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
            result = header_result(response, 'application/json', 401)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'POST':
      if 'application/json' in request.accept_mimetypes:
         if 'application/json' in request.content_type:
            try:
               payload = verify_jwt(request)
               owner = payload['sub']
               content = request.get_json()
               new_load = datastore.entity.Entity(key=client.key(LOADS))
               new_load.update({'volume': content['volume'], 'content': content['content'], 'creation_date': content['creation_date'], 'carrier': []})
               client.put(new_load)
               response = load_response(new_load, True)
               result = header_result(response, 'application/json', 201)
               return (result)
            except KeyError:
               response = error_response('The load is missing at least one of the required attributes, or the HTTP Header is missing an authorization token')
               result = header_result(response, 'application/json', 400)
               return (result)
            except Exception:
               response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
               result = header_result(response, 'application/json', 401)
               return (result)
         else:
            response = error_response("User sent an unsupported media type. Supported media types are: application/json")
            result = header_result(response, 'application/json', 415)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'PUT':
      response = error_response("Method not allowed. Allowed methods for /loads are: GET, POST")
      result = header_result(response, 'application/json', 405)
      return (result)
   elif request.method == 'PATCH':
      response = error_response("Method not allowed. Allowed methods for /loads are: GET, POST")
      result = header_result(response, 'application/json', 405)
      return (result)
   elif request.method == 'DELETE':
      response = error_response("Method not allowed. Allowed methods for /loads are: GET, POST")
      result = header_result(response, 'application/json', 405)
      return (result)
   else:
      return 'Method not recognized'


@app.route('/loads/<load_id>', methods=['GET','DELETE','PUT','PATCH', 'POST'])
def load_get_delete_put_patch(load_id):
   if request.method == 'GET':
      if 'application/json' in request.accept_mimetypes:
         try:
            payload = verify_jwt(request)
            owner = payload['sub']
            load_key = client.key(LOADS, int(load_id))
            load = client.get(key=load_key)
            response = load_response(load, False)
            carriers = response['carrier']
            for carrier in carriers:
               carrier['self'] = "https://" + request.host + '/boats/' + str(carrier['id'])
            result = header_result(response, 'application/json', 200)
            return (result)
         except AttributeError:
            response = error_response('No load with this load_id exists')
            result = header_result(response, 'application/json', 403)
            return (result)
         except Exception:
            response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
            result = header_result(response, 'application/json', 401)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'DELETE':
      if 'application/json' in request.accept_mimetypes:
         try:
            payload = verify_jwt(request)
            owner = payload['sub']
            load_key = client.key(LOADS, int(load_id))
            load = client.get(key=load_key)
            load.get('id')
            query = client.query(kind=BOATS)
            boats_list = list(query.fetch())
            for boat in boats_list:
               boat_loads = boat['loads']
               for item in boat_loads:
                  if item.id == load.get('id'):
                     boat_loads.remove(item)
                     client.put(boat)
            client.delete(load_key)
            result = header_result('', 'application/json', 204)
            return (result)
         except AttributeError:
            response = error_response('No load with this load_id exists')
            result = header_result(response, 'application/json', 403)
            return (result)
         except Exception:
            response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
            result = header_result(response, 'application/json', 401)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'PUT':
      if 'application/json' in request.accept_mimetypes:
         if 'application/json' in request.content_type:
            try:
               payload = verify_jwt(request)
               owner = payload['sub']
               content = request.get_json()
               load_key = client.key(LOADS, int(load_id))
               load = client.get(key=load_key)
               load.get('id')
               load.update({"volume": content["volume"], "content": content["content"], "creation_date": content["creation_date"]})
               client.put(load)
               response = load_response(load, False)
               result = header_result(response, 'application/json', 200)
               return (result)
            except KeyError:
               response = error_response("The load is missing at least one of the required attributes, or the HTTP Header is missing an authorization token")
               result = header_result(response, 'application/json', 400)
               return (result)
            except AttributeError:
               response = error_response('No load with this load_id exists')
               result = header_result(response, 'application/json', 403)
               return (result)
            except Exception:
               response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
               result = header_result(response, 'application/json', 401)
               return (result)
         else:
            response = error_response("User sent an unsupported media type. Supported media types are: application/json")
            result = header_result(response, 'application/json', 415)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'PATCH':
      if 'application/json' in request.accept_mimetypes:
         if 'application/json' in request.content_type:
            try:
               payload = verify_jwt(request)
               owner = payload['sub']
               content = request.get_json()
               load_key = client.key(LOADS, int(load_id))
               load = client.get(key=load_key)
               load.get('id')
               query = client.query(kind=LOADS)
               load_list = list(query.fetch())
               for key, value in content.items():
                  if key == 'volume':
                     load.update({key: content[key]})
                  elif key == 'content':
                     load.update({key: content[key]})
                  elif key == 'creation_date':
                     load.update({key: content[key]})
                  else:
                     response = error_response("The load is missing at least one of the required attributes.")
                     result = header_result(response, 'application/json', 400)
                     return (result)
               client.put(load)
               response = load_response(load, False)
               result = header_result(response, 'application/json', 200)
               return (result)
            except KeyError:
               response = error_response("The boat is missing at least one of the required attributes, or the HTTP Header is missing an authorization token")
               result = header_result(response, 'application/json', 400)
               return (result)
            except AttributeError:
               response = error_response('No load with this load_id exists')
               result = header_result(response, 'application/json', 403)
               return (result)
            except Exception:
               response = error_response("Invalid header. Use an RS256 signed JWT Access Token")
               result = header_result(response, 'application/json', 401)
               return (result)
         else:
            response = error_response("User sent an unsupported media type. Supported media types are: application/json")
            result = header_result(response, 'application/json', 415)
            return (result)
      else:
         response = error_response("User requested an unsupported media type. Supported media types are: application/json")
         result = header_result(response, 'application/json', 406)
         return (result)
   elif request.method == 'POST':
      response = error_response("Method not allowed. Allowed methods for /loads/<load_id> are: GET, PUT, PATCH, DELETE")
      result = header_result(response, 'application/json', 405)
      return (result)
   else:
      return 'Method not recognized'

################# Page Routes #####################################

@app.route('/login', methods=['POST'])
def login_user():
   content = request.get_json()
   username = content["username"]
   password = content["password"]
   body = {'grant_type':'password','username':username,
         'password':password,
         'client_id':CLIENT_ID,
         'client_secret':CLIENT_SECRET
         }
   headers = { 'content-type': 'application/json' }
   url = 'https://' + DOMAIN + '/oauth/token'
   r = requests.post(url, json=body, headers=headers)
   return r.text, 200, {'Content-Type':'application/json'}

@app.route('/')
def welcome():
   return render_template('welcome.html')

@app.route('/userinfo')
@requires_auth
def user_page():
   jwt = session['JWT']
   userinfo = session['profile']
   user_id = userinfo['user_id']
   user_name = userinfo['name']
   add_user_to_db(user_id, user_name)
   return render_template('userInfo.html', JWT = jwt, USER_ID = user_id)


@app.route('/callback')
def callback_handling():

   jwt = auth0.authorize_access_token()['id_token']
   session['JWT'] = jwt
   resp = auth0.get('userinfo')
   userinfo = resp.json()
   session['jwt_payload'] = userinfo
   session['profile'] = {
      'user_id': userinfo['sub'],
      'name': userinfo['name'],
      'picture': userinfo['picture']
   }
   return redirect('/userinfo')


@app.route('/ui_login')
def ui_login():
   return auth0.authorize_redirect(redirect_uri=CALLBACK_URL)


@app.route('/logout')
def logout():
   session.clear()
   params = {'returnTo': url_for('welcome', _external=True), 'client_id': CLIENT_ID}
   return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


####################### HELPER FUNCTIONS ##################################

def add_user_to_db(auth, name):
   new_user = datastore.entity.Entity(key=client.key(USERS))
   new_user.update({"name": name, "user_id": auth})
   client.put(new_user)

def boat_response(new_boat, needs_id):
   boat = dict()
   boat['id'] = new_boat.key.id
   boat['name'] = new_boat['name']
   boat['type'] = new_boat['type']
   boat['length'] = new_boat['length']
   boat['owner'] = new_boat['owner']
   boat['loads'] = new_boat['loads']
   boat['self'] = get_self_url_id(new_boat) if needs_id else request.base_url
   return boat

def user_response(new_user, needs_id):
   user = dict()
   user['id'] = new_user.key.id
   user['name'] = new_user['name']
   user['user_id'] = new_user['user_id']
   user['self'] = get_self_url_id(new_user) if needs_id else request.base_url
   return user

def load_response(new_load, needs_id):
   load = dict()
   load['id'] = new_load.key.id
   load['volume'] = new_load['volume']
   load['content'] = new_load['content']
   load['creation_date'] = new_load['creation_date']
   load['carrier'] = new_load.get('carrier') # For null safety
   load['self'] = get_self_url_id(new_load) if needs_id else request.base_url
   return load

def boat_load_object(load):
   boat_load = dict()
   boat_load['id'] = load.key.id
   return boat_load

def load_list_response(new_load, id):
   load = dict()
   load['id'] = id
   load['volume'] = new_load['volume']
   load['content'] = new_load['content']
   load['creation_date'] = new_load['creation_date']
   load['carrier'] = new_load.get('carrier') # For null safety
   this_load = load['carrier']
   this_load[0]['self'] = "https://" + request.host + '/boats/' + str(this_load[0]['id'])
   load['carrier'] = this_load
   load['self'] = "https://" + request.host + '/loads/' + str(id)
   return load

def load_carrier_object(boat):
   carrier = dict()
   carrier['id'] = boat.key.id
   carrier['name'] = boat['name']
   return carrier

def error_response(message):
   response = dict()
   response['Error'] = message
   return response

def header_result(message, type, status):
   result = make_response(message)
   result.mimetype = type
   result.status_code = status
   return result

def get_self_url_id(item):
   url = request.base_url + '/' + str(item.key.id)
   return url

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
