#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import logging
import json
import os
import time


logger = logging.getLogger(__name__)


def offset_to_unix(seconds):
    return int(1000 * (seconds + time.time()))


def reformat_token(response, client_id):
    token = response["Response"]
    token.update({
        "clientId": client_id,
        "token": token["access_token"],
        "expiresAt": offset_to_unix(token["expires_in"]),
        "refreshToken": token["refresh_token"],
        "refreshExpiresAt": offset_to_unix(token["refresh_expires_in"])
    })
    # token.update({
    #     "cookies": response["Cookies"]
    # })
    return token


class KeycloakApiSession(object):
    def __init__(self):
        self.config_file_location = os.path.join(
            os.environ["HOME"], ".keycloak", "kcadm.config")
        self.realm = 'master'
        self.request_timeout_sec = 2
        self.endpoints = {}
        self.login_endpoint = "/protocol/openid-connect/token"
        self.jar = requests.cookies.RequestsCookieJar()

    def login(self, serverUrl, username, password):
        # Try to open config file...
        logger.info("Base URL: {}".format(serverUrl))
        self.serverUrl = serverUrl
        if os.path.exists(self.config_file_location):
            self.open_config_file(self.config_file_location)
            if not self.check_token(self.get_current_token()):
                self.login_to_server(serverUrl, username, password)
                self.write_config_file(self.config_file_location)
        else:
            # No existing config, get a fresh token
            self.login_to_server(serverUrl, username, password)
            self.write_config_file(self.config_file_location)

    def open_config_file(self, file_location):
        with open(file_location, "r") as f:
            data = json.load(f)
            self.realm = data["realm"]
            self.serverUrl = data["serverUrl"]
            self.endpoints = data["endpoints"]
        # for domain, realmdata in self.endpoints.items():
        #     for realm, data in realmdata.items():
        #         if "cookies" in data.keys():
        #             cookies = data["cookies"]
        #             for k, v in cookies.items():
        #                 print("Setting cookie {}: {} (domain={})".format(
        #                     k, v, domain))
        #                 self.jar.set(k, v, domain=domain, path="/")

    def write_config_file(self, file_location):
        with open(file_location, "w") as f:
            data = {
                "realm": self.realm,
                "serverUrl": self.serverUrl,
                "endpoints": self.endpoints
            }
            f.write(json.dumps(data))

    def login_to_server(self, serverUrl, username, password):
        client_id = "admin-cli"
        response = self.request(
            method="POST",
            endpoint=self._rurl(self.login_endpoint),
            data={
                "client_id": client_id,
                "grant_type": "password",
                "username": username,
                "password": password
            },
            auth=None
        )
        if response:
            print("Logged into admin CLI")
            token = reformat_token(response, client_id)
            self.endpoints[serverUrl] = {self.realm: token}

    def check_token(self, token):
        at_time = ((token["expiresAt"] / 1000) - time.time())
        rt_time = ((token["refreshExpiresAt"] / 1000) - time.time())
        if (at_time < 0):
            print("Access token has expired {0:.2f}s ago".format(at_time))
            if (rt_time < 0):
                print("Refresh token expired {0:.2f}s ago".format(rt_time))
                return False
            else:
                print("Refresh token is valid ({0:.2f}s left)".format(rt_time))
                return self.refresh_token(token)
        else:
            print("Access token is still valid ({0:.2f}s left)".format(at_time))
            return token

    def refresh_token(self, token):
        client_id = "admin-cli"
        response = self.request(
            method="POST",
            endpoint=self._rurl(self.login_endpoint),
            data={
                "client_id": client_id,
                "client_secret": token["session_state"],
                "grant_type": "refresh_token",
                "refresh_token": token["refreshToken"]
            },
            auth=None
        )
        if response:
            print("Refreshed Token")
            token = reformat_token(response, client_id)
            self.endpoints[self.serverUrl] = {self.realm: token}
            if self.config_file_location:
                self.write_config_file(self.config_file_location)
            return token
        else:
            return False

    def get_current_token(self):
        return self.endpoints[self.serverUrl][self.realm]

    def _rurl(self, endpoint, realm_name=None):
        # Helper function for nice URLs
        if not realm_name:
            realm_name = self.realm
        return "{base}/realms/{realm}{endpoint}".format(**{
            "base": self.serverUrl,
            "realm": realm_name,
            "endpoint": endpoint
        })

    def _admurl(self, endpoint):
        # Helper function for nice URLs
        return "{base}/admin/realms{endpoint}".format(**{
            "base": self.serverUrl,
            "endpoint": endpoint
        })

    def _url(self, endpoint):
        # Helper function for nice URLs
        return "{base}{endpoint}".format(**{
            "base": self.serverUrl,
            "endpoint": endpoint
        })

    def get_auth(self):
        token = self.check_token(self.get_current_token())
        if not token:
            raise RuntimeError("You must log in again")
        return {"Authorization": "bearer {}".format(token["token"])}

    def request(
            self, method, endpoint, data=None, headers={}, auth="Bearer",
            params={}
            ):
        if auth == "Bearer":
            headers.update(self.get_auth())
        response = requests.request(
            method=method,
            url=endpoint,
            data=data,
            headers=headers,
            timeout=self.request_timeout_sec,
            cookies=self.jar,
            params=params
        )
        print("{method} {endpoint} {status}".format(
            method=method,
            endpoint=endpoint,
            status=response.status_code
        ))
        if response:
            try:
                msg = response.json()
            except Exception:
                msg = response.text
            rval = {
                "Status": response.status_code,
                "Response": msg
            }
            if response.cookies:
                self.jar.update(response.cookies)
            return rval
        else:
            print("Error {code} {message}".format(
                code=response.status_code,
                message=response.reason
            ))
            response.raise_for_status()


class KeycloakApiClient(object):
    def __init__(self, session):
        self.session = session


###
#   Start API methods
#   See here: http://www.keycloak.org/docs-api/2.5/rest-api/index.html#_definitions
###


class Mappers(KeycloakApiClient):
    """
    Protocol Mappers
    """
    def __init__(self, session):
        self.client_name = "Mappers"
        super(Mappers, self).__init__(session)


    def create_mapper(self, id, realm, reps):
        """
        Create multiple mappers (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        reps : None
            (Required, Body)
        """

        path = "/{realm}/client-templates/{id}/protocol-mappers/add-models".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=reps,
        )

    def create_mapper(self, id, realm, rep):
        """
        Create a mapper (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        rep : ProtocolMapperRepresentation
            (Required, Body)
        """

        path = "/{realm}/client-templates/{id}/protocol-mappers/models".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def get_mappers(self, id, realm):
        """
        Get mappers (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates/{id}/protocol-mappers/models".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_mapper_by_id(self, id, realm):
        """
        Get mapper by id (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) Mapper id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates/{id}/protocol-mappers/models/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update(self, id, realm, rep):
        """
        Update the mapper (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) Mapper id
        realm : string
            (Required, Path) realm name (not id!)
        rep : ProtocolMapperRepresentation
            (Required, Body)
        """

        path = "/{realm}/client-templates/{id}/protocol-mappers/models/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def delete(self, id, realm):
        """
        Delete the mapper (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) Mapper id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates/{id}/protocol-mappers/models/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_mappers_per_protocol(self, id, protocol, realm):
        """
        Get mappers by name for a specific protocol (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) id of client template (not name)
        protocol : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates/{id}/protocol-mappers/protocol/{protocol}".format(
            id=id, protocol=protocol, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def create_mapper(self, id, realm, reps):
        """
        Create multiple mappers (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        reps : None
            (Required, Body)
        """

        path = "/{realm}/clients/{id}/protocol-mappers/add-models".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=reps,
        )

    def create_mapper(self, id, realm, rep):
        """
        Create a mapper (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        rep : ProtocolMapperRepresentation
            (Required, Body)
        """

        path = "/{realm}/clients/{id}/protocol-mappers/models".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def get_mappers(self, id, realm):
        """
        Get mappers (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/protocol-mappers/models".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_mapper_by_id(self, id, realm):
        """
        Get mapper by id (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) Mapper id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/protocol-mappers/models/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update(self, id, realm, rep):
        """
        Update the mapper (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) Mapper id
        realm : string
            (Required, Path) realm name (not id!)
        rep : ProtocolMapperRepresentation
            (Required, Body)
        """

        path = "/{realm}/clients/{id}/protocol-mappers/models/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def delete(self, id, realm):
        """
        Delete the mapper (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) Mapper id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/protocol-mappers/models/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_mappers_per_protocol(self, id, protocol, realm):
        """
        Get mappers by name for a specific protocol (Protocol Mappers)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        protocol : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/protocol-mappers/protocol/{protocol}".format(
            id=id, protocol=protocol, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )


class AttackDetection(KeycloakApiClient):
    """
    Attack Detection
    """
    def __init__(self, session):
        self.client_name = "AttackDetection"
        super(AttackDetection, self).__init__(session)


    def clear_all_brute_force(self, realm):
        """
        Clear any user login failures for all users   This can release temporary disabled users (Attack Detection)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/attack-detection/brute-force/users".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def brute_force_user_status(self, realm, userId):
        """
        Get status of a username in brute force detection (Attack Detection)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        userId : string
            (Required, Path)
        """

        path = "/{realm}/attack-detection/brute-force/users/{userId}".format(
            realm=realm, userId=userId
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def clear_brute_force_for_user(self, realm, userId):
        """
        Clear any user login failures for the user   This can release temporary disabled user (Attack Detection)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        userId : string
            (Required, Path)
        """

        path = "/{realm}/attack-detection/brute-force/users/{userId}".format(
            realm=realm, userId=userId
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )


class Root(KeycloakApiClient):
    """
    Root
    """
    def __init__(self, session):
        self.client_name = "Root"
        super(Root, self).__init__(session)


    def get_info(self, ):
        """
        Get themes, social providers, auth providers, and event listeners available on this server (Root)

        Parameters
        ----------
        """

        path = "/".format(

        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def preflight(self, ):
        """
        CORS preflight (Root)

        Parameters
        ----------
        """

        path = "/{any}".format(

        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="OPTIONS",
            endpoint=self.session._admurl(path),
            params=params,
        )


class Key(KeycloakApiClient):
    """
    Key
    """
    def __init__(self, session):
        self.client_name = "Key"
        super(Key, self).__init__(session)


    def get_key_metadata(self, realm):
        """
        GET /{realm}/keys (Key)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/keys".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )


class Roles(KeycloakApiClient):
    """
    Roles
    """
    def __init__(self, session):
        self.client_name = "Roles"
        super(Roles, self).__init__(session)


    def create_role_for_client_id(self, id, realm, rep):
        """
        Create a new role for the realm or client (Roles)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        rep : RoleRepresentation
            (Required, Body)
        """

        path = "/{realm}/clients/{id}/roles".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def list_roles_for_client_id(self, id, realm):
        """
        Get all roles for the realm or client (Roles)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/roles".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_client_role(self, id, realm, role_name):
        """
        Get a role by name (Roles)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        """

        path = "/{realm}/clients/{id}/roles/{role_name}".format(
            id=id, realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update_client_role(self, id, realm, role_name, rep):
        """
        Update a role by name (Roles)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        rep : RoleRepresentation
            (Required, Body)
        """

        path = "/{realm}/clients/{id}/roles/{role_name}".format(
            id=id, realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def delete_client_role(self, id, realm, role_name):
        """
        Delete a role by name (Roles)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        """

        path = "/{realm}/clients/{id}/roles/{role_name}".format(
            id=id, realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_role_composites_by_client_id(self, id, realm, role_name, roles):
        """
        Add a composite to the role (Roles)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/clients/{id}/roles/{role_name}/composites".format(
            id=id, realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def list_role_composites_by_client_id(self, id, realm, role_name):
        """
        Get composites of the role (Roles)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        """

        path = "/{realm}/clients/{id}/roles/{role_name}/composites".format(
            id=id, realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete_client_role_composites(self, id, realm, role_name, roles):
        """
        Remove roles from the role’s composite (Roles)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        roles : None
            (Required, Body) roles to remove
        """

        path = "/{realm}/clients/{id}/roles/{role_name}/composites".format(
            id=id, realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_role_composites_by_client_id(self, client, id, realm, role_name):
        """
        An app-level roles for the specified app for the role’s composite (Roles)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        """

        path = "/{realm}/clients/{id}/roles/{role_name}/composites/clients/{client}".format(
            client=client, id=id, realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_role_composites_by_client_id(self, id, realm, role_name):
        """
        Get realm-level roles of the role’s composite (Roles)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        """

        path = "/{realm}/clients/{id}/roles/{role_name}/composites/realm".format(
            id=id, realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_client_role_management_permissions(self, id, realm, role_name):
        """
        Return object stating whether role Authoirzation permissions have been initialized or not and a reference (Roles)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path)
        """

        path = "/{realm}/clients/{id}/roles/{role_name}/management/permissions".format(
            id=id, realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def set_client_role_management_permissions_enabled(self, id, realm, role_name, ref):
        """
        Return object stating whether role Authoirzation permissions have been initialized or not and a reference (Roles)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path)
        ref : ManagementPermissionReference
            (Required, Body)
        """

        path = "/{realm}/clients/{id}/roles/{role_name}/management/permissions".format(
            id=id, realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=ref,
        )

    def get_users_in_client_role(self, id, realm, role_name, first=None, max=None):
        """
        Return List of Users that have the specified role name (Roles)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path)
        first : integer(int32)
            (Optional, Query)
        max : integer(int32)
            (Optional, Query)
        """

        path = "/{realm}/clients/{id}/roles/{role_name}/users".format(
            id=id, realm=realm, role_name=role_name
        )
        params = {
            "first": first, "max": max
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def create_role(self, realm, rep):
        """
        Create a new role for the realm or client (Roles)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        rep : RoleRepresentation
            (Required, Body)
        """

        path = "/{realm}/roles".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def list_roles(self, realm):
        """
        Get all roles for the realm or client (Roles)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/roles".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_role(self, realm, role_name):
        """
        Get a role by name (Roles)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        """

        path = "/{realm}/roles/{role_name}".format(
            realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update_role(self, realm, role_name, rep):
        """
        Update a role by name (Roles)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        rep : RoleRepresentation
            (Required, Body)
        """

        path = "/{realm}/roles/{role_name}".format(
            realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def delete_role(self, realm, role_name):
        """
        Delete a role by name (Roles)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        """

        path = "/{realm}/roles/{role_name}".format(
            realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_role_composites(self, realm, role_name, roles):
        """
        Add a composite to the role (Roles)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/roles/{role_name}/composites".format(
            realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_role_composites(self, realm, role_name):
        """
        Get composites of the role (Roles)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        """

        path = "/{realm}/roles/{role_name}/composites".format(
            realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete_role_composites(self, realm, role_name, roles):
        """
        Remove roles from the role’s composite (Roles)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        roles : None
            (Required, Body) roles to remove
        """

        path = "/{realm}/roles/{role_name}/composites".format(
            realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_client_id_role_composites(self, client, realm, role_name):
        """
        An app-level roles for the specified app for the role’s composite (Roles)

        Parameters
        ----------
        client : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        """

        path = "/{realm}/roles/{role_name}/composites/clients/{client}".format(
            client=client, realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_realm_role_composites(self, realm, role_name):
        """
        Get realm-level roles of the role’s composite (Roles)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path) role’s name (not id!)
        """

        path = "/{realm}/roles/{role_name}/composites/realm".format(
            realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_management_permissions(self, realm, role_name):
        """
        Return object stating whether role Authoirzation permissions have been initialized or not and a reference (Roles)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path)
        """

        path = "/{realm}/roles/{role_name}/management/permissions".format(
            realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def set_management_permissions_enabled(self, realm, role_name, ref):
        """
        Return object stating whether role Authoirzation permissions have been initialized or not and a reference (Roles)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path)
        ref : ManagementPermissionReference
            (Required, Body)
        """

        path = "/{realm}/roles/{role_name}/management/permissions".format(
            realm=realm, role_name=role_name
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=ref,
        )

    def get_users_in_role(self, realm, role_name, first=None, max=None):
        """
        Return List of Users that have the specified role name (Roles)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_name : string
            (Required, Path)
        first : integer(int32)
            (Optional, Query)
        max : integer(int32)
            (Optional, Query)
        """

        path = "/{realm}/roles/{role_name}/users".format(
            realm=realm, role_name=role_name
        )
        params = {
            "first": first, "max": max
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_role(self, realm, role_id):
        """
        Get a specific role’s representation (Roles (by ID))

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_id : string
            (Required, Path) id of role
        """

        path = "/{realm}/roles-by-id/{role_id}".format(
            realm=realm, role_id=role_id
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update_role(self, realm, role_id, rep):
        """
        Update the role (Roles (by ID))

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_id : string
            (Required, Path) id of role
        rep : RoleRepresentation
            (Required, Body)
        """

        path = "/{realm}/roles-by-id/{role_id}".format(
            realm=realm, role_id=role_id
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def delete_role(self, realm, role_id):
        """
        Delete the role (Roles (by ID))

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_id : string
            (Required, Path) id of role
        """

        path = "/{realm}/roles-by-id/{role_id}".format(
            realm=realm, role_id=role_id
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_composites(self, realm, role_id, roles):
        """
        Make the role a composite role by associating some child roles (Roles (by ID))

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_id : string
            (Required, Path)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/roles-by-id/{role_id}/composites".format(
            realm=realm, role_id=role_id
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_role_composites(self, realm, role_id):
        """
        Get role’s children   Returns a set of role’s children provided the role is a composite. (Roles (by ID))

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_id : string
            (Required, Path)
        """

        path = "/{realm}/roles-by-id/{role_id}/composites".format(
            realm=realm, role_id=role_id
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete_composites(self, realm, role_id, roles):
        """
        Remove a set of roles from the role’s composite (Roles (by ID))

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_id : string
            (Required, Path) Role id
        roles : None
            (Required, Body) A set of roles to be removed
        """

        path = "/{realm}/roles-by-id/{role_id}/composites".format(
            realm=realm, role_id=role_id
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_client_role_composites(self, client, realm, role_id):
        """
        Get client-level roles for the client that are in the role’s composite (Roles (by ID))

        Parameters
        ----------
        client : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        role_id : string
            (Required, Path)
        """

        path = "/{realm}/roles-by-id/{role_id}/composites/clients/{client}".format(
            client=client, realm=realm, role_id=role_id
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_realm_role_composites(self, realm, role_id):
        """
        Get realm-level roles that are in the role’s composite (Roles (by ID))

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_id : string
            (Required, Path)
        """

        path = "/{realm}/roles-by-id/{role_id}/composites/realm".format(
            realm=realm, role_id=role_id
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_management_permissions(self, realm, role_id):
        """
        Return object stating whether role Authoirzation permissions have been initialized or not and a reference (Roles (by ID))

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_id : string
            (Required, Path)
        """

        path = "/{realm}/roles-by-id/{role_id}/management/permissions".format(
            realm=realm, role_id=role_id
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def set_management_permissions_enabled(self, realm, role_id, ref):
        """
        Return object stating whether role Authoirzation permissions have been initialized or not and a reference (Roles (by ID))

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        role_id : string
            (Required, Path)
        ref : ManagementPermissionReference
            (Required, Body)
        """

        path = "/{realm}/roles-by-id/{role_id}/management/permissions".format(
            realm=realm, role_id=role_id
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=ref,
        )


class UserStorageProvider(KeycloakApiClient):
    """
    User Storage Provider
    """
    def __init__(self, session):
        self.client_name = "UserStorageProvider"
        super(UserStorageProvider, self).__init__(session)


    def get_simple_name(self, id, realm):
        """
        Need this for admin console to display simple name of provider when displaying user detail   KEYCLOAK-4328 (User Storage Provider)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/user-storage/{id}/name".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def remove_imported_users(self, id, realm):
        """
        Remove imported users (User Storage Provider)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/user-storage/{id}/remove-imported-users".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def sync_users(self, id, realm, action=None):
        """
        Trigger sync of users   Action can be "triggerFullSync" or "triggerChangedUsersSync" (User Storage Provider)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        action : string
            (Optional, Query)
        """

        path = "/{realm}/user-storage/{id}/sync".format(
            id=id, realm=realm
        )
        params = {
            "action": action
        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def unlink_users(self, id, realm):
        """
        Unlink imported users from a storage provider (User Storage Provider)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/user-storage/{id}/unlink-users".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def sync_mapper_data(self, id, parentId, realm, direction=None):
        """
        Trigger sync of mapper data related to ldap mapper (roles, groups, …​)   direction is "fedToKeycloak" or "keycloakToFed" (User Storage Provider)

        Parameters
        ----------
        id : string
            (Required, Path)
        parentId : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        direction : string
            (Optional, Query)
        """

        path = "/{realm}/user-storage/{parentId}/mappers/{id}/sync".format(
            id=id, parentId=parentId, realm=realm
        )
        params = {
            "direction": direction
        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )


class AuthManagement(KeycloakApiClient):
    """
    Authentication Management
    """
    def __init__(self, session):
        self.client_name = "AuthManagement"
        super(AuthManagement, self).__init__(session)


    def get_authenticator_providers(self, realm):
        """
        Get authenticator providers   Returns a list of authenticator providers. (Authentication Management)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/authenticator-providers".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_client_authenticator_providers(self, realm):
        """
        Get client authenticator providers   Returns a list of client authenticator providers. (Authentication Management)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/client-authenticator-providers".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_authenticator_config_description(self, providerId, realm):
        """
        Get authenticator provider’s configuration description (Authentication Management)

        Parameters
        ----------
        providerId : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/config-description/{providerId}".format(
            providerId=providerId, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_authenticator_config(self, id, realm):
        """
        Get authenticator configuration (Authentication Management)

        Parameters
        ----------
        id : string
            (Required, Path) Configuration id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/config/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update_authenticator_config(self, id, realm, rep):
        """
        Update authenticator configuration (Authentication Management)

        Parameters
        ----------
        id : string
            (Required, Path) Configuration id
        realm : string
            (Required, Path) realm name (not id!)
        rep : AuthenticatorConfigRepresentation
            (Required, Body) JSON describing new state of authenticator configuration
        """

        path = "/{realm}/authentication/config/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def remove_authenticator_config(self, id, realm):
        """
        Delete authenticator configuration (Authentication Management)

        Parameters
        ----------
        id : string
            (Required, Path) Configuration id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/config/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_execution(self, realm, execution):
        """
        Add new authentication execution (Authentication Management)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        execution : AuthenticationExecutionRepresentation
            (Required, Body) JSON model describing authentication execution
        """

        path = "/{realm}/authentication/executions".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=execution,
        )

    def remove_execution(self, executionId, realm):
        """
        Delete execution (Authentication Management)

        Parameters
        ----------
        executionId : string
            (Required, Path) Execution id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/executions/{executionId}".format(
            executionId=executionId, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def new_executionconfig(self, executionId, realm, json):
        """
        Update execution with new configuration (Authentication Management)

        Parameters
        ----------
        executionId : string
            (Required, Path) Execution id
        realm : string
            (Required, Path) realm name (not id!)
        json : AuthenticatorConfigRepresentation
            (Required, Body) JSON with new configuration
        """

        path = "/{realm}/authentication/executions/{executionId}/config".format(
            executionId=executionId, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=json,
        )

    def lower_priority(self, executionId, realm):
        """
        Lower execution’s priority (Authentication Management)

        Parameters
        ----------
        executionId : string
            (Required, Path) Execution id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/executions/{executionId}/lower-priority".format(
            executionId=executionId, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def raise_priority(self, executionId, realm):
        """
        Raise execution’s priority (Authentication Management)

        Parameters
        ----------
        executionId : string
            (Required, Path) Execution id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/executions/{executionId}/raise-priority".format(
            executionId=executionId, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def create_flow(self, realm, flow):
        """
        Create a new authentication flow (Authentication Management)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        flow : AuthenticationFlowRepresentation
            (Required, Body) Authentication flow representation
        """

        path = "/{realm}/authentication/flows".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=flow,
        )

    def get_flows(self, realm):
        """
        Get authentication flows   Returns a list of authentication flows. (Authentication Management)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/flows".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def copy(self, flowAlias, realm, data):
        """
        Copy existing authentication flow under a new name   The new name is given as 'newName' attribute of the passed JSON object (Authentication Management)

        Parameters
        ----------
        flowAlias : string
            (Required, Path) Name of the existing authentication flow
        realm : string
            (Required, Path) realm name (not id!)
        data : Map
            (Required, Body) JSON containing 'newName' attribute
        """

        path = "/{realm}/authentication/flows/{flowAlias}/copy".format(
            flowAlias=flowAlias, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=data,
        )

    def get_executions(self, flowAlias, realm):
        """
        Get authentication executions for a flow (Authentication Management)

        Parameters
        ----------
        flowAlias : string
            (Required, Path) Flow alias
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/flows/{flowAlias}/executions".format(
            flowAlias=flowAlias, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update_executions(self, flowAlias, realm, rep):
        """
        Update authentication executions of a flow (Authentication Management)

        Parameters
        ----------
        flowAlias : string
            (Required, Path) Flow alias
        realm : string
            (Required, Path) realm name (not id!)
        rep : AuthenticationExecutionInfoRepresentation
            (Required, Body)
        """

        path = "/{realm}/authentication/flows/{flowAlias}/executions".format(
            flowAlias=flowAlias, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def add_execution(self, flowAlias, realm, data):
        """
        Add new authentication execution to a flow (Authentication Management)

        Parameters
        ----------
        flowAlias : string
            (Required, Path) Alias of parent flow
        realm : string
            (Required, Path) realm name (not id!)
        data : Map
            (Required, Body) New execution JSON data containing 'provider' attribute
        """

        path = "/{realm}/authentication/flows/{flowAlias}/executions/execution".format(
            flowAlias=flowAlias, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=data,
        )

    def add_execution_flow(self, flowAlias, realm, data):
        """
        Add new flow with new execution to existing flow (Authentication Management)

        Parameters
        ----------
        flowAlias : string
            (Required, Path) Alias of parent authentication flow
        realm : string
            (Required, Path) realm name (not id!)
        data : Map
            (Required, Body) New authentication flow / execution JSON data containing 'alias', 'type', 'provider', and 'description' attributes
        """

        path = "/{realm}/authentication/flows/{flowAlias}/executions/flow".format(
            flowAlias=flowAlias, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=data,
        )

    def get_flow(self, id, realm):
        """
        Get authentication flow for id (Authentication Management)

        Parameters
        ----------
        id : string
            (Required, Path) Flow id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/flows/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete_flow(self, id, realm):
        """
        Delete an authentication flow (Authentication Management)

        Parameters
        ----------
        id : string
            (Required, Path) Flow id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/flows/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_form_action_providers(self, realm):
        """
        Get form action providers   Returns a list of form action providers. (Authentication Management)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/form-action-providers".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_form_providers(self, realm):
        """
        Get form providers   Returns a list of form providers. (Authentication Management)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/form-providers".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_per_client_config_description(self, realm):
        """
        Get configuration descriptions for all clients (Authentication Management)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/per-client-config-description".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def register_required_action(self, realm, data):
        """
        Register a new required actions (Authentication Management)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        data : Map
            (Required, Body) JSON containing 'providerId', and 'name' attributes.
        """

        path = "/{realm}/authentication/register-required-action".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=data,
        )

    def get_required_actions(self, realm):
        """
        Get required actions   Returns a list of required actions. (Authentication Management)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/required-actions".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_required_action(self, alias, realm):
        """
        Get required action for alias (Authentication Management)

        Parameters
        ----------
        alias : string
            (Required, Path) Alias of required action
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/required-actions/{alias}".format(
            alias=alias, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update_required_action(self, alias, realm, rep):
        """
        Update required action (Authentication Management)

        Parameters
        ----------
        alias : string
            (Required, Path) Alias of required action
        realm : string
            (Required, Path) realm name (not id!)
        rep : RequiredActionProviderRepresentation
            (Required, Body) JSON describing new state of required action
        """

        path = "/{realm}/authentication/required-actions/{alias}".format(
            alias=alias, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def remove_required_action(self, alias, realm):
        """
        Delete required action (Authentication Management)

        Parameters
        ----------
        alias : string
            (Required, Path) Alias of required action
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/required-actions/{alias}".format(
            alias=alias, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_unregistered_required_actions(self, realm):
        """
        Get unregistered required actions   Returns a list of unregistered required actions. (Authentication Management)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/authentication/unregistered-required-actions".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )


class ClientAttributeCertificate(KeycloakApiClient):
    """
    Client Attribute Certificate
    """
    def __init__(self, session):
        self.client_name = "ClientAttributeCertificate"
        super(ClientAttributeCertificate, self).__init__(session)


    def get_key_info(self, attr, id, realm):
        """
        Get key info (Client Attribute Certificate)

        Parameters
        ----------
        attr : string
            (Required, Path)
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/certificates/{attr}".format(
            attr=attr, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_key_store(self, attr, id, realm, config):
        """
        Get a keystore file for the client, containing private key and public certificate (Client Attribute Certificate)

        Parameters
        ----------
        attr : string
            (Required, Path)
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        config : KeyStoreConfig
            (Required, Body) Keystore configuration as JSON
        """

        path = "/{realm}/clients/{id}/certificates/{attr}/download".format(
            attr=attr, id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=config,
        )

    def generate(self, attr, id, realm):
        """
        Generate a new certificate with new key pair (Client Attribute Certificate)

        Parameters
        ----------
        attr : string
            (Required, Path)
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/certificates/{attr}/generate".format(
            attr=attr, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def generate_and_get_key_store(self, attr, id, realm, config):
        """
        Generate a new keypair and certificate, and get the private key file   Generates a keypair and certificate and serves the private key in a specified keystore format. (Client Attribute Certificate)

        Parameters
        ----------
        attr : string
            (Required, Path)
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        config : KeyStoreConfig
            (Required, Body) Keystore configuration as JSON
        """

        path = "/{realm}/clients/{id}/certificates/{attr}/generate-and-download".format(
            attr=attr, id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=config,
        )

    def upload_jks(self, attr, id, realm, input):
        """
        Upload certificate and eventually private key (Client Attribute Certificate)

        Parameters
        ----------
        attr : string
            (Required, Path)
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        input : file
            (Required, FormData)
        """

        path = "/{realm}/clients/{id}/certificates/{attr}/upload".format(
            attr=attr, id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "multipart/form-data"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def upload_jks_certificate(self, attr, id, realm, input):
        """
        Upload only certificate, not private key (Client Attribute Certificate)

        Parameters
        ----------
        attr : string
            (Required, Path)
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        input : file
            (Required, FormData)
        """

        path = "/{realm}/clients/{id}/certificates/{attr}/upload-certificate".format(
            attr=attr, id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "multipart/form-data"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )


class Clients(KeycloakApiClient):
    """
    Clients
    """
    def __init__(self, session):
        self.client_name = "Clients"
        super(Clients, self).__init__(session)


    def create_client(self, realm, rep):
        """
        Create a new client   Client’s client_id must be unique! (Clients)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        rep : ClientRepresentation
            (Required, Body)
        """

        path = "/{realm}/clients".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def get_clients(self, realm, clientId=None, viewableOnly=None):
        """
        Get clients belonging to the realm   Returns a list of clients belonging to the realm (Clients)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        clientId : string
            (Optional, Query) filter by clientId
        viewableOnly : boolean
            (Optional, Query) filter clients that cannot be viewed in full by admin
        """

        path = "/{realm}/clients".format(
            realm=realm
        )
        params = {
            "clientId": clientId, "viewableOnly": viewableOnly
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_client(self, id, realm):
        """
        Get representation of the client (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update(self, id, realm, rep):
        """
        Update the client (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        rep : ClientRepresentation
            (Required, Body)
        """

        path = "/{realm}/clients/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def delete_client(self, id, realm):
        """
        Delete the client (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def regenerate_secret(self, id, realm):
        """
        Generate a new secret for the client (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/client-secret".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_client_secret(self, id, realm):
        """
        Get the client secret (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/client-secret".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_in_stall_ationprovider(self, id, providerId, realm):
        """
        GET /{realm}/clients/{id}/installation/providers/{providerId} (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        providerId : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/installation/providers/{providerId}".format(
            id=id, providerId=providerId, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_management_permissions(self, id, realm):
        """
        Return object stating whether client Authorization permissions have been initialized or not and a reference (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/management/permissions".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def set_management_permissions_enabled(self, id, realm, ref):
        """
        Return object stating whether client Authorization permissions have been initialized or not and a reference (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        ref : ManagementPermissionReference
            (Required, Body)
        """

        path = "/{realm}/clients/{id}/management/permissions".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=ref,
        )

    def register_node(self, id, realm, formParams):
        """
        Register a cluster node with the client   Manually register cluster node to this client - usually it’s not needed to call this directly as adapter should handle  by sending registration request to Keycloak (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        formParams : Map
            (Required, Body)
        """

        path = "/{realm}/clients/{id}/nodes".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=formParams,
        )

    def unregister_node(self, id, node, realm):
        """
        Unregister a cluster node from the client (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        node : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/nodes/{node}".format(
            id=id, node=node, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_offline_session_count(self, id, realm):
        """
        Get application offline session count   Returns a number of offline user sessions associated with this client   {      "count": number  } (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/offline-session-count".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_offline_user_sessions(self, id, realm, first=None, max=None):
        """
        Get offline sessions for client   Returns a list of offline user sessions associated with this client (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        first : integer(int32)
            (Optional, Query) Paging offset
        max : integer(int32)
            (Optional, Query) Maximum results size (defaults to 100)
        """

        path = "/{realm}/clients/{id}/offline-sessions".format(
            id=id, realm=realm
        )
        params = {
            "first": first, "max": max
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def push_revocation(self, id, realm):
        """
        Push the client’s revocation policy to its admin URL   If the client has an admin URL, push revocation policy to it. (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/push-revocation".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def regenerate_registration_access_token(self, id, realm):
        """
        Generate a new registration access token for the client (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/registration-access-token".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_service_account_user(self, id, realm):
        """
        Get a user dedicated to the service account (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/service-account-user".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_application_session_count(self, id, realm):
        """
        Get application session count   Returns a number of user sessions associated with this client   {      "count": number  } (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/session-count".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def test_nodes_available(self, id, realm):
        """
        Test if registered cluster nodes are available   Tests availability by sending 'ping' request to all cluster nodes. (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/test-nodes-available".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_user_sessions(self, id, realm, first=None, max=None):
        """
        Get user sessions for client   Returns a list of user sessions associated with this client (Clients)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        first : integer(int32)
            (Optional, Query) Paging offset
        max : integer(int32)
            (Optional, Query) Maximum results size (defaults to 100)
        """

        path = "/{realm}/clients/{id}/user-sessions".format(
            id=id, realm=realm
        )
        params = {
            "first": first, "max": max
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )


class Component(KeycloakApiClient):
    """
    Component
    """
    def __init__(self, session):
        self.client_name = "Component"
        super(Component, self).__init__(session)


    def create(self, realm, rep):
        """
        POST /{realm}/components (Component)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        rep : ComponentRepresentation
            (Required, Body)
        """

        path = "/{realm}/components".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def get_components(self, realm, name=None, parent=None, type=None):
        """
        GET /{realm}/components (Component)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        name : string
            (Optional, Query)
        parent : string
            (Optional, Query)
        type : string
            (Optional, Query)
        """

        path = "/{realm}/components".format(
            realm=realm
        )
        params = {
            "name": name, "parent": parent, "type": type
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_component(self, id, realm):
        """
        GET /{realm}/components/{id} (Component)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/components/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update_component(self, id, realm, rep):
        """
        PUT /{realm}/components/{id} (Component)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        rep : ComponentRepresentation
            (Required, Body)
        """

        path = "/{realm}/components/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def remove_component(self, id, realm):
        """
        DELETE /{realm}/components/{id} (Component)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/components/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_subcomponentconfig(self, id, realm, type=None):
        """
        List of subcomponent types that are available to configure for a particular parent component. (Component)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        type : string
            (Optional, Query)
        """

        path = "/{realm}/components/{id}/sub-component-types".format(
            id=id, realm=realm
        )
        params = {
            "type": type
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )


class ClientInitialAccess(KeycloakApiClient):
    """
    Client Initial Access
    """
    def __init__(self, session):
        self.client_name = "ClientInitialAccess"
        super(ClientInitialAccess, self).__init__(session)


    def create(self, realm, config):
        """
        Create a new initial access token. (Client Initial Access)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        config : ClientInitialAccessCreatePresentation
            (Required, Body)
        """

        path = "/{realm}/clients-initial-access".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=config,
        )

    def list(self, realm):
        """
        GET /{realm}/clients-initial-access (Client Initial Access)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients-initial-access".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete(self, id, realm):
        """
        DELETE /{realm}/clients-initial-access/{id} (Client Initial Access)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients-initial-access/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )


class ClientRoleMappings(KeycloakApiClient):
    """
    Client Role Mappings
    """
    def __init__(self, session):
        self.client_name = "ClientRoleMappings"
        super(ClientRoleMappings, self).__init__(session)


    def add_client_role_mapping(self, client, id, realm, roles):
        """
        Add client-level roles to the user role mapping (Client Role Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/groups/{id}/role-mappings/clients/{client}".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_client_role_mappings(self, client, id, realm):
        """
        Get client-level role mappings for the user, and the app (Client Role Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/groups/{id}/role-mappings/clients/{client}".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete_client_role_mapping(self, client, id, realm, roles):
        """
        Delete client-level roles from user role mapping (Client Role Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/groups/{id}/role-mappings/clients/{client}".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_available_client_role_mappings(self, client, id, realm):
        """
        Get available client-level roles that can be mapped to the user (Client Role Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/groups/{id}/role-mappings/clients/{client}/available".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_composite_client_role_mappings(self, client, id, realm):
        """
        Get effective client-level role mappings   This recurses any composite roles (Client Role Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/groups/{id}/role-mappings/clients/{client}/composite".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_client_role_mapping(self, client, id, realm, roles):
        """
        Add client-level roles to the user role mapping (Client Role Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/users/{id}/role-mappings/clients/{client}".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_client_role_mappings(self, client, id, realm):
        """
        Get client-level role mappings for the user, and the app (Client Role Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/role-mappings/clients/{client}".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete_client_role_mapping(self, client, id, realm, roles):
        """
        Delete client-level roles from user role mapping (Client Role Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/users/{id}/role-mappings/clients/{client}".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_available_client_role_mappings(self, client, id, realm):
        """
        Get available client-level roles that can be mapped to the user (Client Role Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/role-mappings/clients/{client}/available".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_composite_client_role_mappings(self, client, id, realm):
        """
        Get effective client-level role mappings   This recurses any composite roles (Client Role Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/role-mappings/clients/{client}/composite".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )


class RoleMapper(KeycloakApiClient):
    """
    Role Mapper
    """
    def __init__(self, session):
        self.client_name = "RoleMapper"
        super(RoleMapper, self).__init__(session)


    def get_role_mappings(self, id, realm):
        """
        Get role mappings (Role Mapper)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/groups/{id}/role-mappings".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_realm_role_mappings(self, id, realm, roles):
        """
        Add realm-level role mappings to the user (Role Mapper)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body) Roles to add
        """

        path = "/{realm}/groups/{id}/role-mappings/realm".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_realm_role_mappings(self, id, realm):
        """
        Get realm-level role mappings (Role Mapper)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/groups/{id}/role-mappings/realm".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete_realm_role_mappings(self, id, realm, roles):
        """
        Delete realm-level role mappings (Role Mapper)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/groups/{id}/role-mappings/realm".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_available_realm_role_mappings(self, id, realm):
        """
        Get realm-level roles that can be mapped (Role Mapper)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/groups/{id}/role-mappings/realm/available".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_composite_realm_role_mappings(self, id, realm):
        """
        Get effective realm-level role mappings   This will recurse all composite roles to get the result. (Role Mapper)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/groups/{id}/role-mappings/realm/composite".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_role_mappings(self, id, realm):
        """
        Get role mappings (Role Mapper)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/role-mappings".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_realm_role_mappings(self, id, realm, roles):
        """
        Add realm-level role mappings to the user (Role Mapper)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body) Roles to add
        """

        path = "/{realm}/users/{id}/role-mappings/realm".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_realm_role_mappings(self, id, realm):
        """
        Get realm-level role mappings (Role Mapper)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/role-mappings/realm".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete_realm_role_mappings(self, id, realm, roles):
        """
        Delete realm-level role mappings (Role Mapper)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/users/{id}/role-mappings/realm".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_available_realm_role_mappings(self, id, realm):
        """
        Get realm-level roles that can be mapped (Role Mapper)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/role-mappings/realm/available".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_composite_realm_role_mappings(self, id, realm):
        """
        Get effective realm-level role mappings   This will recurse all composite roles to get the result. (Role Mapper)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/role-mappings/realm/composite".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )


class ScopeMappings(KeycloakApiClient):
    """
    Scope Mappings
    """
    def __init__(self, session):
        self.client_name = "ScopeMappings"
        super(ScopeMappings, self).__init__(session)


    def get_scope_mappings(self, id, realm):
        """
        Get all scope mappings for the client (Scope Mappings)

        Parameters
        ----------
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates/{id}/scope-mappings".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_client_scope_mapping(self, client, id, realm, roles):
        """
        Add client-level roles to the client’s scope (Scope Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/client-templates/{id}/scope-mappings/clients/{client}".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_client_scope_mappings(self, client, id, realm):
        """
        Get the roles associated with a client’s scope   Returns roles for the client. (Scope Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates/{id}/scope-mappings/clients/{client}".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete_client_scope_mapping(self, client, id, realm, roles):
        """
        Remove client-level roles from the client’s scope. (Scope Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/client-templates/{id}/scope-mappings/clients/{client}".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_available_client_scope_mappings(self, client, id, realm):
        """
        The available client-level roles   Returns the roles for the client that can be associated with the client’s scope (Scope Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates/{id}/scope-mappings/clients/{client}/available".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_composite_client_scope_mappings(self, client, id, realm):
        """
        Get effective client roles   Returns the roles for the client that are associated with the client’s scope. (Scope Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates/{id}/scope-mappings/clients/{client}/composite".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_realm_scope_mappings(self, id, realm, roles):
        """
        Add a set of realm-level roles to the client’s scope (Scope Mappings)

        Parameters
        ----------
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/client-templates/{id}/scope-mappings/realm".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_realm_scope_mappings(self, id, realm):
        """
        Get realm-level roles associated with the client’s scope (Scope Mappings)

        Parameters
        ----------
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates/{id}/scope-mappings/realm".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete_realm_scope_mappings(self, id, realm, roles):
        """
        Remove a set of realm-level roles from the client’s scope (Scope Mappings)

        Parameters
        ----------
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/client-templates/{id}/scope-mappings/realm".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_available_realm_scope_mappings(self, id, realm):
        """
        Get realm-level roles that are available to attach to this client’s scope (Scope Mappings)

        Parameters
        ----------
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates/{id}/scope-mappings/realm/available".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_composite_realm_scope_mappings(self, id, realm):
        """
        Get effective realm-level roles associated with the client’s scope   What this does is recurse  any composite roles associated with the client’s scope and adds the roles to this lists. (Scope Mappings)

        Parameters
        ----------
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates/{id}/scope-mappings/realm/composite".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_scope_mappings(self, id, realm):
        """
        Get all scope mappings for the client (Scope Mappings)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/scope-mappings".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_client_scope_mapping(self, client, id, realm, roles):
        """
        Add client-level roles to the client’s scope (Scope Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/clients/{id}/scope-mappings/clients/{client}".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_client_scope_mappings(self, client, id, realm):
        """
        Get the roles associated with a client’s scope   Returns roles for the client. (Scope Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/scope-mappings/clients/{client}".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete_client_scope_mapping(self, client, id, realm, roles):
        """
        Remove client-level roles from the client’s scope. (Scope Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/clients/{id}/scope-mappings/clients/{client}".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_available_client_scope_mappings(self, client, id, realm):
        """
        The available client-level roles   Returns the roles for the client that can be associated with the client’s scope (Scope Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/scope-mappings/clients/{client}/available".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_composite_client_scope_mappings(self, client, id, realm):
        """
        Get effective client roles   Returns the roles for the client that are associated with the client’s scope. (Scope Mappings)

        Parameters
        ----------
        client : string
            (Required, Path)
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/scope-mappings/clients/{client}/composite".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_realm_scope_mappings(self, id, realm, roles):
        """
        Add a set of realm-level roles to the client’s scope (Scope Mappings)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/clients/{id}/scope-mappings/realm".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_realm_scope_mappings(self, id, realm):
        """
        Get realm-level roles associated with the client’s scope (Scope Mappings)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/scope-mappings/realm".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete_realm_scope_mappings(self, id, realm, roles):
        """
        Remove a set of realm-level roles from the client’s scope (Scope Mappings)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        roles : None
            (Required, Body)
        """

        path = "/{realm}/clients/{id}/scope-mappings/realm".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=roles,
        )

    def get_available_realm_scope_mappings(self, id, realm):
        """
        Get realm-level roles that are available to attach to this client’s scope (Scope Mappings)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/scope-mappings/realm/available".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_composite_realm_scope_mappings(self, id, realm):
        """
        Get effective realm-level roles associated with the client’s scope   What this does is recurse  any composite roles associated with the client’s scope and adds the roles to this lists. (Scope Mappings)

        Parameters
        ----------
        id : string
            (Required, Path) id of client (not client-id)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clients/{id}/scope-mappings/realm/composite".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )


class ClientTemplates(KeycloakApiClient):
    """
    Client Templates
    """
    def __init__(self, session):
        self.client_name = "ClientTemplates"
        super(ClientTemplates, self).__init__(session)


    def create_client_template(self, realm, rep):
        """
        Create a new client template   Client Template’s name must be unique! (Client Templates)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        rep : ClientTemplateRepresentation
            (Required, Body)
        """

        path = "/{realm}/client-templates".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def get_client_templates(self, realm):
        """
        Get client templates belonging to the realm   Returns a list of client templates belonging to the realm (Client Templates)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_client(self, id, realm):
        """
        Get representation of the client template (Client Templates)

        Parameters
        ----------
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update(self, id, realm, rep):
        """
        Update the client template (Client Templates)

        Parameters
        ----------
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        rep : ClientTemplateRepresentation
            (Required, Body)
        """

        path = "/{realm}/client-templates/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def delete_client_template(self, id, realm):
        """
        Delete the client template (Client Templates)

        Parameters
        ----------
        id : string
            (Required, Path) id of client template (not name)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-templates/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )


class Groups(KeycloakApiClient):
    """
    Groups
    """
    def __init__(self, session):
        self.client_name = "Groups"
        super(Groups, self).__init__(session)


    def add_top_level_group(self, realm, rep):
        """
        create or add a top level realm groupSet or create child. (Groups)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        rep : GroupRepresentation
            (Required, Body)
        """

        path = "/{realm}/groups".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def get_groups(self, realm, first=None, max=None, search=None):
        """
        Get group hierarchy. (Groups)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        first : integer(int32)
            (Optional, Query)
        max : integer(int32)
            (Optional, Query)
        search : string
            (Optional, Query)
        """

        path = "/{realm}/groups".format(
            realm=realm
        )
        params = {
            "first": first, "max": max, "search": search
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_group_count(self, realm, search=None, top=None):
        """
        Returns the groups counts. (Groups)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        search : string
            (Optional, Query)
        top : boolean
            (Optional, Query)
        """

        path = "/{realm}/groups/count".format(
            realm=realm
        )
        params = {
            "search": search, "top": top
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_group(self, id, realm):
        """
        GET /{realm}/groups/{id} (Groups)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/groups/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update_group(self, id, realm, rep):
        """
        Update group, ignores subgroups. (Groups)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        rep : GroupRepresentation
            (Required, Body)
        """

        path = "/{realm}/groups/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def delete_group(self, id, realm):
        """
        DELETE /{realm}/groups/{id} (Groups)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/groups/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_child(self, id, realm, rep):
        """
        Set or create child. (Groups)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        rep : GroupRepresentation
            (Required, Body)
        """

        path = "/{realm}/groups/{id}/children".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def get_management_permissions(self, id, realm):
        """
        Return object stating whether client Authorization permissions have been initialized or not and a reference (Groups)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/groups/{id}/management/permissions".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def set_management_permissions_enabled(self, id, realm, ref):
        """
        Return object stating whether client Authorization permissions have been initialized or not and a reference (Groups)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        ref : ManagementPermissionReference
            (Required, Body)
        """

        path = "/{realm}/groups/{id}/management/permissions".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=ref,
        )

    def get_members(self, id, realm, first=None, max=None):
        """
        Get users   Returns a list of users, filtered according to query parameters (Groups)

        Parameters
        ----------
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        first : integer(int32)
            (Optional, Query) Pagination offset
        max : integer(int32)
            (Optional, Query) Maximum results size (defaults to 100)
        """

        path = "/{realm}/groups/{id}/members".format(
            id=id, realm=realm
        )
        params = {
            "first": first, "max": max
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )


class Users(KeycloakApiClient):
    """
    Users
    """
    def __init__(self, session):
        self.client_name = "Users"
        super(Users, self).__init__(session)


    def create_user(self, realm, rep):
        """
        Create a new user   Username must be unique. (Users)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        rep : UserRepresentation
            (Required, Body)
        """

        path = "/{realm}/users".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def get_users(self, realm, email=None, first=None, firstName=None, lastName=None, max=None, search=None, username=None):
        """
        Get users   Returns a list of users, filtered according to query parameters (Users)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        email : string
            (Optional, Query)
        first : integer(int32)
            (Optional, Query)
        firstName : string
            (Optional, Query)
        lastName : string
            (Optional, Query)
        max : integer(int32)
            (Optional, Query) Maximum results size (defaults to 100)
        search : string
            (Optional, Query) A String contained in username, first or last name, or email
        username : string
            (Optional, Query)
        """

        path = "/{realm}/users".format(
            realm=realm
        )
        params = {
            "email": email, "first": first, "firstName": firstName, "lastName": lastName, "max": max, "search": search, "username": username
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_users_count(self, realm):
        """
        GET /{realm}/users/count (Users)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/count".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_user(self, id, realm):
        """
        Get representation of the user (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update_user(self, id, realm, rep):
        """
        Update the user (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        rep : UserRepresentation
            (Required, Body)
        """

        path = "/{realm}/users/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def delete_user(self, id, realm):
        """
        Delete the user (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_consents(self, id, realm):
        """
        Get consents granted by the user (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/consents".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def revoke_consent(self, client, id, realm):
        """
        Revoke consent and offline tokens for particular client from user (Users)

        Parameters
        ----------
        client : string
            (Required, Path) Client id
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/consents/{client}".format(
            client=client, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def disable_credential_type(self, id, realm, credentialTypes):
        """
        Disable all credentials for a user of a specific type (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        credentialTypes : < string > array
            (Required, Body)
        """

        path = "/{realm}/users/{id}/disable-credential-types".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=credentialTypes,
        )

    def execute_actions_email(self, id, realm, actions, client_id=None, lifespan=None, redirect_uri=None):
        """
        Send a update account email to the user   An email contains a link the user can click to perform a set of required actions. (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        client_id : string
            (Optional, Query) Client id
        lifespan : integer(int32)
            (Optional, Query) Number of seconds after which the generated token expires
        redirect_uri : string
            (Optional, Query) Redirect uri
        actions : < string > array
            (Required, Body) required actions the user needs to complete
        """

        path = "/{realm}/users/{id}/execute-actions-email".format(
            id=id, realm=realm
        )
        params = {
            "client_id": client_id, "lifespan": lifespan, "redirect_uri": redirect_uri
        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=actions,
        )

    def get_federated_identity(self, id, realm):
        """
        Get social logins associated with the user (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/federated-identity".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_federated_identity(self, id, provider, realm, rep):
        """
        Add a social login provider to the user (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        provider : string
            (Required, Path) Social login provider id
        realm : string
            (Required, Path) realm name (not id!)
        rep : FederatedIdentityRepresentation
            (Required, Body)
        """

        path = "/{realm}/users/{id}/federated-identity/{provider}".format(
            id=id, provider=provider, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def remove_federated_identity(self, id, provider, realm):
        """
        Remove a social login provider from user (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        provider : string
            (Required, Path) Social login provider id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/federated-identity/{provider}".format(
            id=id, provider=provider, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_group_membership(self, id, realm):
        """
        GET /{realm}/users/{id}/groups (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/groups".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def join_group(self, groupId, id, realm):
        """
        PUT /{realm}/users/{id}/groups/{groupId} (Users)

        Parameters
        ----------
        groupId : string
            (Required, Path)
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/groups/{groupId}".format(
            groupId=groupId, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def remove_membership(self, groupId, id, realm):
        """
        DELETE /{realm}/users/{id}/groups/{groupId} (Users)

        Parameters
        ----------
        groupId : string
            (Required, Path)
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/groups/{groupId}".format(
            groupId=groupId, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def impersonate(self, id, realm):
        """
        Impersonate the user (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/impersonation".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def logout(self, id, realm):
        """
        Remove all user sessions associated with the user   Also send notification to all clients that have an admin URL to invalidate the sessions for the particular user. (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/logout".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_offline_sessions(self, clientId, id, realm):
        """
        Get offline sessions associated with the user and client (Users)

        Parameters
        ----------
        clientId : string
            (Required, Path)
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/offline-sessions/{clientId}".format(
            clientId=clientId, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def remove_totp(self, id, realm):
        """
        Remove TOTP from the user (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/remove-totp".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def reset_password(self, id, realm, password):
        """
        Set up a temporary password for the user   User will have to reset the temporary password next time they log in. (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        password : CredentialRepresentation
            (Required, Body) A Temporary password
        """

        path = "/{realm}/users/{id}/reset-passwordword".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=password,
        )

    def send_verify_email(self, id, realm, client_id=None, redirect_uri=None):
        """
        Send an email-verification email to the user   An email contains a link the user can click to verify their email address. (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        client_id : string
            (Optional, Query) Client id
        redirect_uri : string
            (Optional, Query) Redirect uri
        """

        path = "/{realm}/users/{id}/send-verify-email".format(
            id=id, realm=realm
        )
        params = {
            "client_id": client_id, "redirect_uri": redirect_uri
        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_sessions(self, id, realm):
        """
        Get sessions associated with the user (Users)

        Parameters
        ----------
        id : string
            (Required, Path) User id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users/{id}/sessions".format(
            id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )


class ClientRegistrationPolicy(KeycloakApiClient):
    """
    Client Registration Policy
    """
    def __init__(self, session):
        self.client_name = "ClientRegistrationPolicy"
        super(ClientRegistrationPolicy, self).__init__(session)


    def get_providers(self, realm):
        """
        Base path for retrieve providers with the configProperties properly filled (Client Registration Policy)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-registration-policy/providers".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )


class IdentityProviders(KeycloakApiClient):
    """
    Identity Providers
    """
    def __init__(self, session):
        self.client_name = "IdentityProviders"
        super(IdentityProviders, self).__init__(session)


    def import_from(self, realm, input):
        """
        Import identity provider from uploaded JSON file (Identity Providers)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        input : file
            (Required, FormData)
        """

        path = "/{realm}/identity-provider/import-config".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "multipart/form-data"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def create(self, realm, representation):
        """
        Create a new identity provider (Identity Providers)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        representation : IdentityProviderRepresentation
            (Required, Body) JSON body
        """

        path = "/{realm}/identity-provider/instances".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=representation,
        )

    def get_identity_providers(self, realm):
        """
        Get identity providers (Identity Providers)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/identity-provider/instances".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_identity_provider(self, alias, realm):
        """
        Get the identity provider (Identity Providers)

        Parameters
        ----------
        alias : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/identity-provider/instances/{alias}".format(
            alias=alias, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update(self, alias, realm, providerRep):
        """
        Update the identity provider (Identity Providers)

        Parameters
        ----------
        alias : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        providerRep : IdentityProviderRepresentation
            (Required, Body)
        """

        path = "/{realm}/identity-provider/instances/{alias}".format(
            alias=alias, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=providerRep,
        )

    def delete(self, alias, realm):
        """
        Delete the identity provider (Identity Providers)

        Parameters
        ----------
        alias : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/identity-provider/instances/{alias}".format(
            alias=alias, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def export(self, alias, realm, format=None):
        """
        Export public broker configuration for identity provider (Identity Providers)

        Parameters
        ----------
        alias : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        format : string
            (Optional, Query) Format to use
        """

        path = "/{realm}/identity-provider/instances/{alias}/export".format(
            alias=alias, realm=realm
        )
        params = {
            "format": format
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_management_permissions(self, alias, realm):
        """
        Return object stating whether client Authorization permissions have been initialized or not and a reference (Identity Providers)

        Parameters
        ----------
        alias : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/identity-provider/instances/{alias}/management/permissions".format(
            alias=alias, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def set_management_permissions_enabled(self, alias, realm, ref):
        """
        Return object stating whether client Authorization permissions have been initialized or not and a reference (Identity Providers)

        Parameters
        ----------
        alias : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        ref : ManagementPermissionReference
            (Required, Body)
        """

        path = "/{realm}/identity-provider/instances/{alias}/management/permissions".format(
            alias=alias, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=ref,
        )

    def get_mapper_types(self, alias, realm):
        """
        Get mapper types for identity provider (Identity Providers)

        Parameters
        ----------
        alias : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/identity-provider/instances/{alias}/mapper-types".format(
            alias=alias, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_mapper(self, alias, realm, mapper):
        """
        Add a mapper to identity provider (Identity Providers)

        Parameters
        ----------
        alias : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        mapper : IdentityProviderMapperRepresentation
            (Required, Body)
        """

        path = "/{realm}/identity-provider/instances/{alias}/mappers".format(
            alias=alias, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=mapper,
        )

    def get_mappers(self, alias, realm):
        """
        Get mappers for identity provider (Identity Providers)

        Parameters
        ----------
        alias : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/identity-provider/instances/{alias}/mappers".format(
            alias=alias, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_mapper_by_id(self, alias, id, realm):
        """
        Get mapper by id for the identity provider (Identity Providers)

        Parameters
        ----------
        alias : string
            (Required, Path)
        id : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/identity-provider/instances/{alias}/mappers/{id}".format(
            alias=alias, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update(self, alias, id, realm, rep):
        """
        Update a mapper for the identity provider (Identity Providers)

        Parameters
        ----------
        alias : string
            (Required, Path)
        id : string
            (Required, Path) Mapper id
        realm : string
            (Required, Path) realm name (not id!)
        rep : IdentityProviderMapperRepresentation
            (Required, Body)
        """

        path = "/{realm}/identity-provider/instances/{alias}/mappers/{id}".format(
            alias=alias, id=id, realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def delete(self, alias, id, realm):
        """
        Delete a mapper for the identity provider (Identity Providers)

        Parameters
        ----------
        alias : string
            (Required, Path)
        id : string
            (Required, Path) Mapper id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/identity-provider/instances/{alias}/mappers/{id}".format(
            alias=alias, id=id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_identity_providers(self, provider_id, realm):
        """
        Get identity providers (Identity Providers)

        Parameters
        ----------
        provider_id : string
            (Required, Path) Provider id
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/identity-provider/providers/{provider_id}".format(
            provider_id=provider_id, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )


class Realms(KeycloakApiClient):
    """
    Realms Admin
    """
    def __init__(self, session):
        self.client_name = "Realms"
        super(Realms, self).__init__(session)


    def import_realm(self, rep):
        """
        Import a realm   Imports a realm from a full representation of that realm. (Realms Admin)

        Parameters
        ----------
        rep : RealmRepresentation
            (Required, Body) JSON representation of the realm
        """

        path = "/".format(

        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def get_realm(self, realm):
        """
        Get the top-level representation of the realm   It will not include nested information like User and Client representations. (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update_realm(self, realm, rep):
        """
        Update the top-level information of the realm   Any user, roles or client information in the representation  will be ignored. (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        rep : RealmRepresentation
            (Required, Body)
        """

        path = "/{realm}".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def delete_realm(self, realm):
        """
        Delete the realm (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_events(self, realm, authClient=None, authIpAddress=None, authRealm=None, authUser=None, dateFrom=None, dateTo=None, first=None, max=None, operationTypes=None, resourcePath=None, resourceTypes=None):
        """
        Get admin events   Returns all admin events, or filters events based on URL query parameters listed here (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        authClient : string
            (Optional, Query)
        authIpAddress : string
            (Optional, Query)
        authRealm : string
            (Optional, Query)
        authUser : string
            (Optional, Query) user id
        dateFrom : string
            (Optional, Query)
        dateTo : string
            (Optional, Query)
        first : integer(int32)
            (Optional, Query)
        max : integer(int32)
            (Optional, Query) Maximum results size (defaults to 100)
        operationTypes : < string > array(csv)
            (Optional, Query)
        resourcePath : string
            (Optional, Query)
        resourceTypes : < string > array(csv)
            (Optional, Query)
        """

        path = "/{realm}/admin-events".format(
            realm=realm
        )
        params = {
            "authClient": authClient, "authIpAddress": authIpAddress, "authRealm": authRealm, "authUser": authUser, "dateFrom": dateFrom, "dateTo": dateTo, "first": first, "max": max, "operationTypes": operationTypes, "resourcePath": resourcePath, "resourceTypes": resourceTypes
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def clear_admin_events(self, realm):
        """
        Delete all admin events (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/admin-events".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def clear_key_scache(self, realm):
        """
        Clear cache of external public keys (Public keys of clients or Identity providers) (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clear-keys-cache".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def clear_realm_cache(self, realm):
        """
        Clear realm cache (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clear-realm-cache".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def clear_user_cache(self, realm):
        """
        Clear user cache (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/clear-user-cache".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def convert_client_description(self, realm, description):
        """
        Base path for importing clients under this realm. (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        description : string
            (Required, Body)
        """

        path = "/{realm}/client-description-converter".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=description,
        )

    def get_client_session_stats(self, realm):
        """
        Get client session stats   Returns a JSON map. (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/client-session-stats".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_default_groups(self, realm):
        """
        Get group hierarchy. (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/default-groups".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def add_default_group(self, groupId, realm):
        """
        PUT /{realm}/default-groups/{groupId} (Realms Admin)

        Parameters
        ----------
        groupId : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/default-groups/{groupId}".format(
            groupId=groupId, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def remove_default_group(self, groupId, realm):
        """
        DELETE /{realm}/default-groups/{groupId} (Realms Admin)

        Parameters
        ----------
        groupId : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/default-groups/{groupId}".format(
            groupId=groupId, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_events(self, realm, client=None, dateFrom=None, dateTo=None, first=None, ipAddress=None, max=None, type=None, user=None):
        """
        Get events   Returns all events, or filters them based on URL query parameters listed here (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        client : string
            (Optional, Query) App or oauth client name
        dateFrom : string
            (Optional, Query) From date
        dateTo : string
            (Optional, Query) To date
        first : integer(int32)
            (Optional, Query) Paging offset
        ipAddress : string
            (Optional, Query) IP address
        max : integer(int32)
            (Optional, Query) Maximum results size (defaults to 100)
        type : < string > array(csv)
            (Optional, Query) The types of events to return
        user : string
            (Optional, Query) User id
        """

        path = "/{realm}/events".format(
            realm=realm
        )
        params = {
            "client": client, "dateFrom": dateFrom, "dateTo": dateTo, "first": first, "ipAddress": ipAddress, "max": max, "type": type, "user": user
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def clear_events(self, realm):
        """
        Delete all events (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/events".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_realm_events_config(self, realm):
        """
        Get the events provider configuration   Returns JSON object with events provider configuration (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/events/config".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def update_realm_events_config(self, realm, rep):
        """
        Update the events provider   Change the events provider and/or its configuration (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        rep : RealmEventsConfigRepresentation
            (Required, Body)
        """

        path = "/{realm}/events/config".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def get_groupby_path(self, path, realm):
        """
        GET /{realm}/group-by-path/{path} (Realms Admin)

        Parameters
        ----------
        path : string
            (Required, Path)
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/group-by-path/{path}".format(
            path=path, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def logout_all(self, realm):
        """
        Removes all user sessions. (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/logout-all".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def partialexport(self, realm, exportClients=None, exportGroupsAndRoles=None):
        """
        Partial export of existing realm into a JSON file. (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        exportClients : boolean
            (Optional, Query)
        exportGroupsAndRoles : boolean
            (Optional, Query)
        """

        path = "/{realm}/partial-export".format(
            realm=realm
        )
        params = {
            "exportClients": exportClients, "exportGroupsAndRoles": exportGroupsAndRoles
        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def partial_import(self, realm, rep):
        """
        Partial import from a JSON file to an existing realm. (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        rep : PartialImportRepresentation
            (Required, Body)
        """

        path = "/{realm}/partialImport".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=rep,
        )

    def push_revocation(self, realm):
        """
        Push the realm’s revocation policy to any client that has an admin url associated with it. (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/push-revocation".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def delete_session(self, realm, session):
        """
        Remove a specific user session. (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        session : string
            (Required, Path)
        """

        path = "/{realm}/sessions/{session}".format(
            realm=realm, session=session
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="DELETE",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def test_ldap_connection(self, realm, action=None, bindCredential=None, bindDn=None, componentId=None, connectionTimeout=None, connectionUrl=None, useTruststoreSpi=None):
        """
        Test LDAP connection (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        action : string
            (Optional, Query)
        bindCredential : string
            (Optional, Query)
        bindDn : string
            (Optional, Query)
        componentId : string
            (Optional, Query)
        connectionTimeout : string
            (Optional, Query)
        connectionUrl : string
            (Optional, Query)
        useTruststoreSpi : string
            (Optional, Query)
        """

        path = "/{realm}/testLDAPConnection".format(
            realm=realm
        )
        params = {
            "action": action, "bindCredential": bindCredential, "bindDn": bindDn, "componentId": componentId, "connectionTimeout": connectionTimeout, "connectionUrl": connectionUrl, "useTruststoreSpi": useTruststoreSpi
        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def test_smtp_connection(self, config, realm):
        """
        Test SMTP connection with current logged in user (Realms Admin)

        Parameters
        ----------
        config : string
            (Required, Path) SMTP server configuration
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/testSMTPConnection/{config}".format(
            config=config, realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="POST",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def get_user_mgmt_permissions(self, realm):
        """
        GET /{realm}/users-management-permissions (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        """

        path = "/{realm}/users-management-permissions".format(
            realm=realm
        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )

    def set_user_smanagement_permissions_enabled(self, realm, ref):
        """
        PUT /{realm}/users-management-permissions (Realms Admin)

        Parameters
        ----------
        realm : string
            (Required, Path) realm name (not id!)
        ref : ManagementPermissionReference
            (Required, Body)
        """

        path = "/{realm}/users-management-permissions".format(
            realm=realm
        )
        params = {

        }
        headers = {
            "Content-Type": "application/json"
        }
        return self.session.request(
            method="PUT",
            endpoint=self.session._admurl(path),
            params=params,
            headers=headers,
            data=ref,
        )

    def list_realms(self, ):
        """
        List security realms (Realms Admin)

        Parameters
        ----------
        """

        path = "".format(

        )
        params = {

        }
        headers = {

        }
        return self.session.request(
            method="GET",
            endpoint=self.session._admurl(path),
            params=params,
        )
