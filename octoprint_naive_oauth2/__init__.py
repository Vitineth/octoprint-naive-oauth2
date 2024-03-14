# coding=utf-8
from __future__ import absolute_import

import secrets

import flask_login
import octoprint.plugin
import requests
from flask import url_for, session, jsonify, request, abort, make_response, g, current_app, render_template
from flask_login import login_user, current_user
from oauthlib.oauth2 import WebApplicationClient
from octoprint.events import eventManager, Events
from octoprint.server.util.flask import get_remote_address, session_signature
from octoprint.vendor.flask_principal import identity_changed, Identity

required_settings = ["client_id", "client_secret", "authorization_url", "token_url", "info_url"]


def is_none_or_empty(s):
    print("testing \"{}\" = {} or {} or {}".format(
        s,
        s is None,
        type(s) is not str,
        len(str(s).strip()) == 0
    ))
    return s is None or type(s) is not str or len(str(s).strip()) == 0


class Naive_oauth2Plugin(octoprint.plugin.SettingsPlugin,
                         octoprint.plugin.AssetPlugin,
                         octoprint.plugin.TemplatePlugin,
                         octoprint.plugin.BlueprintPlugin,
                         octoprint.plugin.UiPlugin,
                         octoprint.plugin.StartupPlugin
                         ):

    def __init__(self):
        super().__init__()
        self.is_plugin_active = True

    def on_startup(self, *args, **kwargs):
        self.is_plugin_active = len([x for x in required_settings if is_none_or_empty(self._settings.get([x]))]) == 0
        if self.is_plugin_active:
            self._logger.info(
                "Found all required config! OAuth2 login will be supported from your authentication provider")
        else:
            self._logger.warn(
                "Missing some required configs - OAuth2 login will not be supported! Missing: " + ",".join(
                    [x for x in required_settings if is_none_or_empty(self._settings.get([x]))])
            )

    # SettingsPlugin mixin

    def get_settings_defaults(self):
        return {
            "client_id": "",
            "client_secret": "",
            "authorization_url": "",
            "token_url": "",
            "info_url": "",
        }

    # AssetPlugin mixin

    def get_assets(self):
        if not self.is_plugin_active:
            return {}

        return {
            "js": ["js/naive_oauth2.js", "js/view_model.js"],
            "css": ["css/naive_oauth2.css"],
            "less": ["less/naive_oauth2.less"]
        }

    # Software Update hook

    def get_update_information(self):
        # Define the configuration for your plugin to use with the Software Update
        # Plugin here. See https://docs.octoprint.org/en/master/bundledplugins/softwareupdate.html
        # for details.
        return {
            "naive_oauth2": {
                "displayName": "Naive_oauth2 Plugin",
                "displayVersion": self._plugin_version,

                # version check: github repository
                "type": "github_release",
                "user": "vitineth",
                "repo": "octoprint-naive-oauth2",
                "current": self._plugin_version,

                # update method: pip
                "pip": "https://github.com/vitineth/octoprint-naive-oauth2/archive/{target_version}.zip",
            }
        }

    # Endpoints

    def is_blueprint_csrf_protected(self):
        return True

    def is_blueprint_protected(self):
        return False

    @octoprint.plugin.BlueprintPlugin.route('/oauth/url', methods=['GET'])
    def get_oauth_url(self):
        if not self.is_plugin_active:
            return abort(429)

        client_id = self._settings.get(['client_id'])
        client = WebApplicationClient(client_id)
        url = self._settings.get(['authorization_url'])
        base_url = url_for("plugin.naive_oauth2.get_oauth_callback", _external=True)
        state = secrets.token_hex(32)
        session['oauth_state'] = state

        request_uri = client.prepare_request_uri(
            url,
            base_url,
            ['profile', 'openid', 'roles'],  # TODO: move ot config
            state
        )

        return jsonify(
            url=request_uri
        )

    @octoprint.plugin.BlueprintPlugin.route('/oauth/callback', methods=['GET'])
    def get_oauth_callback(self):
        if not self.is_plugin_active:
            return abort(429)

        if 'oauth_state' not in session:
            return 'invalid request, no state present', 400

        if 'state' not in request.args:
            return 'invalid request, no state query present', 400
        if 'code' not in request.args:
            return 'invalid request, no code query present', 400

        state = request.args.get('state')
        code = request.args.get('code')

        if state != session['oauth_state']:
            return 'invalid state', 400

        client_id = self._settings.get(['client_id'])
        client_secret = self._settings.get(['client_secret'])
        client = WebApplicationClient(client_id)
        token_url = self._settings.get(['token_url'])
        info_url = self._settings.get(['info_url'])

        data = client.prepare_request_body(
            code=code,
            redirect_uri=url_for("plugin.naive_oauth2.get_oauth_callback", _external=True),
            client_id=client_id,
            client_secret=client_secret
        )

        response = requests.post(token_url, data=data, headers={
            'Content-Type': 'application/x-www-form-urlencoded'})
        client.parse_request_body_response(response.text)

        response = requests.get(info_url, headers={
            'Authorization': 'Bearer {}'.format(client.access_token)
        })
        userinfo = response.json()

        if "usersession.id" in session:
            if "usersession.id" in session:
                del session["usersession.id"]
            if "login_mechanism" in session:
                del session["login_mechanism"]
            octoprint.server.userManager.logout_user(current_user)

        remote_addr = get_remote_address(request)

        user_id = userinfo['sub']
        preferred_username = userinfo['preferred_username']
        roles = userinfo.get('resource_access', {}).get(client_id, {}).get('roles', {})
        groups = [x[6:] for x in roles if x.startswith('group_')]
        permissions = [x[11:] for x in roles if x.startswith('permission_')]
        system_user = octoprint.server.userManager.find_user(user_id)
        if system_user is None:
            self._logger.info(
                f"First login, provisioning new user {user_id} with groups {roles} from {remote_addr}"
            )
            octoprint.server.userManager.add_user(
                user_id,
                secrets.token_hex(128),
                True,
                permissions,
                groups,
                None,
                False
            )
            system_user = octoprint.server.userManager.find_user(user_id)

            self._logger.info(
                f"Resolved user {system_user}"
            )
        elif not system_user.is_active:
            self._logger.error(
                f"Failed oauth login attempt for user {user_id} from {remote_addr}, user is deactivated"
            )
            return abort(403)

        octoprint.server.userManager.change_user_settings(user_id, {
            "oauth.is_oauth_user": "true",
            "oauth.username": preferred_username
        })

        user = octoprint.server.userManager.login_user(system_user)
        session["usersession.id"] = user.session
        session["usersession.signature"] = session_signature(
            user_id, user.session
        )
        g.user = user

        login_user(user)
        identity_changed.send(
            current_app._get_current_object(), identity=Identity(user.get_id())
        )
        session["login_mechanism"] = "oauth"

        self._logger.info(
            "Actively logging in user {} from {} via oauth".format(
                user.get_id(), remote_addr
            )
        )

        response = user.as_dict()
        response["_login_mechanism"] = session["login_mechanism"]

        r = make_response(jsonify(response))
        r.delete_cookie("active_logout")

        eventManager().fire(
            Events.USER_LOGGED_IN, payload={"username": user.get_id()}
        )
        self._logger.info(f"Logging in user {user_id} from {remote_addr} via oauth")

        print(client.token)
        r.status_code = 301
        r.headers.set('Location', url_for("index", _external=False))
        return r

    # UI Overrides

    def will_handle_ui(self, request):
        if not self.is_plugin_active:
            return False

        handle_ui = request.path == "/"
        user = flask_login.current_user
        try:
            handle_ui = handle_ui and user.is_anonymous()
        except Exception:
            handle_ui = True
        return handle_ui

    def get_ui_permissions(self):
        return []

    def on_ui_render(self, now, request, render_kwargs):
        return make_response(
            render_template("login_with_sso.jinja2", **render_kwargs)
        )

    def get_template_configs(self):
        if not self.is_plugin_active:
            return []

        return [
            dict(
                name="Access",
                type="usersettings",
                template="access_replacement.jinja2",
                replaces="access",
            )
        ]


# If you want your plugin to be registered within OctoPrint under a different name than what you defined in setup.py
# ("OctoPrint-PluginSkeleton"), you may define that here. Same goes for the other metadata derived from setup.py that
# can be overwritten via __plugin_xyz__ control properties. See the documentation for that.
__plugin_name__ = "Naive OAuth2"

# Set the Python version your plugin is compatible with below. Recommended is Python 3 only for all new plugins.
# OctoPrint 1.4.0 - 1.7.x run under both Python 3 and the end-of-life Python 2.
# OctoPrint 1.8.0 onwards only supports Python 3.
__plugin_pythoncompat__ = ">=3,<4"  # Only Python 3


def __plugin_load__():
    global __plugin_implementation__
    __plugin_implementation__ = Naive_oauth2Plugin()

    global __plugin_hooks__
    __plugin_hooks__ = {
        "octoprint.plugin.softwareupdate.check_config": __plugin_implementation__.get_update_information
    }
