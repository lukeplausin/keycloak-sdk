# keycloak-sdk
Unofficial SDK for the Keycloak application for Python. This python SDK is compiled from the HTML documentation for the Keycloak API. I found it more usable than the NodeJS SDK and the Java based CLI.

[Keycloak API Reference](http://www.keycloak.org/docs-api/3.4/rest-api/index.html#_componentrepresentation)

## Installation

To install with pip:

```
pip install https://github.com/lukeplausin/keycloak-sdk.git
```

## Usage

Log into a keycloak server (with your username and password stored in the `KC_USERNAME` and `KC_PASSWORD` environment variables):

```
import os
from keycloak_sdk import KeycloakApiSession, Realms, Clients


s = KeycloakApiSession()
s.login(
    serverUrl="https://my.keycloak.server/auth",
    username=os.environ["KC_USERNAME"],
    password=os.environ["KC_PASSWORD"]
)
```

List the security realms on the server:

```
realms_client = Realms(session=s)
response = realms_client.list_realms()
for item in response["Response"]:
    print("Found realm \"{}\" (id: {})".format(item["realm"], item["id"]))
```

List the clients for a particular realm:

```
response = realms_client.list_realms()
realm_name = response[0]["realm"]

clients_client = Clients(session=s)
response = clients_client.get_clients(realm=realm_name)
for item in response["Response"]:
    print("Found client \"{c_name}\" (id: {c_id}) in realm  \"{r_name}\"".format(
        c_name=item["clientId"],
        c_id=item["id"],
        r_name=realm_name
    ))
```

To make any generic call to the API, use the `.request()` method. The function accepts arguments in the same format as the requests module (`requests.request`). The helper function will take care of the auth token for you. You can also use the `KeycloakApiSession._admurl` helper function to prepend the server URL to your path.

```
response = s.request(
    method="GET",
    endpoint=s._admurl("/myrealm/keys")
)
```

## Documentation

To see the list of clients provided in the SDK, use introspection:

```
import keycloak_sdk
print(dir(keycloak_sdk))
```

To see the list of methods in a client, use the `help()` function:

```
from keycloak_sdk import Clients

help(Clients) # Help on the module
help(Clients.get_clients) # Help on a particular function
```

## TODO
* Change print statements to use the python `Logging` module
* Make storing key in the config file optional
* Serialise body type parameters using `json.dumps` when these types of parameters are present
* Compile the module help using `Sphinx`
* Parse different versions of the API docs other than 3.4
* Perform type checking on inputs
* Provide parameter defaults inside the module
* Update the SDK compile script
