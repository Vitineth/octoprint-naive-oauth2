# OctoPrint-Naive-OAuth2

This adds very basic OAuth2 support to OctoPrint. When configured, this will add a 'Sign in with SSO' button to th login
screen which will take you to the auth provider. Users are automatically created on first login.

## Pitfalls

* Usernames do not display
    * We did not want to rely on preferred_username for auth so I used the IDP ID, but this means that their username
      will show up as some random stuff (ie a UUID)
        * Remediation: provide a new user manager which handles oauth users, or use preferred username with support for
          renaming on login and avoiding naming clashes
* Passwords still technically work
    * Usesrs are initialised with a 128 character random password but you can technically login to these accounts as
      normal
        * Remediation: provide a new user manager which disabled password based login for oauth2 users

## Configuration

```yaml
plugins:
  naive_oauth2:
    authorization_url: https://<my-idp>/auth
    client_id: <client-id>
    client_secret: <client-secret>
    info_url: https://<my-idp>/userinfo
    token_url: https://<my-idp>/token
```

## Permissions / Groups

If you setup role mappings for your users, you can use it to grant permissions and groups to the users. Ie if you grant
your user the `group_users` role, we will give the user the `users` role. The same works for `permission_<permission>`.

We currently search for these in the user info response under `resource_access.<client-id>.roles`

## Setup

Install via the bundled [Plugin Manager](https://docs.octoprint.org/en/master/bundledplugins/pluginmanager.html)
or manually using this URL:

    https://github.com/vitineth/octoprint-naive-oauth2/archive/master.zip

**TODO:** Describe how to install your plugin, if more needs to be done than just installing it via pip or through
the plugin manager.

## Configuration

**TODO:** Describe your plugin's configuration options (if any).
