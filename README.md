oidckit
=======

Unobtrusive pluggable OpenID Connect consumer toolkit

Usage
-----

Construct a configuration class and a client class. 
This example is for [Microsoft Identity Platform / Azure AD 2.0](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols) OIDC flows, based on [the published OIDC configuration](https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration).
For other providers, you may wish to also override some of the `Provider` functions.

```python
class AzureADOIDCConfig(OIDCProviderConfiguration):
    op_authorization_endpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
    op_jwks_endpoint = 'https://login.microsoftonline.com/common/discovery/v2.0/keys'
    op_token_endpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
    op_user_endpoint = 'https://graph.microsoft.com/oidc/userinfo'
    rp_scopes = 'openid email profile'
    rp_sign_algo = 'RS256'
    rp_client_id = 'your application ID here'
    rp_client_secret = 'your application secret here'


class AzureADOIDCProvider(OIDCProvider):
    config = AzureADOIDCConfig()
```

In your web framework of choice, implement views/URL endpoints to initiate the OIDC dance and to receive the access code.
This example is for Django, using old-school function-based views.

First, the initiation view. Note you'll need to store the `auth_state` within the authentication request
returned somewhere you can retrieve it when the client is redirected back to the callback view.

```python
def initiate_login(request):
    with AzureADOIDCProvider() as provider:
        auth_req = build_authentication_request(
            provider=provider,
            request=request,
            redirect_uri='http://absolute-url-to-your-callback-view/',
        )
        request.session['auth_state'] = auth_req.auth_state.asdict()
    return HttpResponseRedirect(auth_req.redirect_url)
```

Then, the callback view, using the same provider class, and the state we just stashed.  You'll need to pass the
`code` and `state` querystring parameters the OIDC provider passes to the library, too.

```python
def authentication_callback(request):
    with AzureADOIDCProvider() as provider:
        auth_resp = process_callback_data(
            auth_state=request.session.pop('auth_state'),
            code=request.GET.get('code'),
            provider=provider,
            state=request.GET.get('state'),
        )
```

Congratulations! If everything went fine, `auth_resp` will contain token data from the IDP.
You can use this – according to the instructions of the IDP, of course – to sign up an user, log them in, etc.

For instance, for MSIP, [`auth_resp.decode_id_token()['sub']` will contain an identifier](https://docs.microsoft.com/en-gb/azure/active-directory/develop/id-tokens)
 uniquely identifying the user (for your application!). 

Acknowledgements
----------------

* This project was born as a way to make [`mozilla-django-oidc` project](https://github.com/mozilla/mozilla-django-oidc/)
  less opinionated and less Django-reliant.
