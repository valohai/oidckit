from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from oidckit.provider import OIDCProvider


class AuthenticationState:
    state: str
    redirect_uri: str
    nonce: Optional[str] = None

    def __init__(self, state, redirect_uri, nonce=None):
        self.state = state
        self.redirect_uri = redirect_uri
        self.nonce = nonce

    def asdict(self):
        return vars(self)


class AuthenticationResult:
    provider: "OIDCProvider"
    auth_state: AuthenticationState
    token: dict
    _user_info: Optional[dict] = None
    _decoded_id_token: Optional[dict] = None
    _decoded_access_token: Optional[dict] = None

    def __init__(self, provider, auth_state, token):
        self.provider = provider
        self.auth_state = auth_state
        self.token = token

    @property
    def id_token(self):
        return self.token["id_token"]

    @property
    def access_token(self):
        return self.token["access_token"]

    def get_user_info(self):
        if not self._user_info:
            self._user_info = self.provider.retrieve_user_info(auth_result=self)
        return self._user_info

    def decode_id_token(self) -> dict:
        if not self._decoded_id_token:
            self._decoded_id_token = self.provider.decode_token(
                self.id_token, nonce=self.auth_state.nonce
            )
        return self._decoded_id_token

    def decode_access_token(self, verify: bool = True) -> dict:
        """
        Try to decode the access token, if any, of the token payload.
        This will only succeed if the token actually _is_ a JWT token.

        The token data may occasionally be signed in a way that defies
        signature verification by mortal means.  You can pass `verify=False`
        to bypass this verification.  However, `id_token` must always be
        verifiable, which is why the `decode_id_token()` function does not
        let you shoot yourself in the foot by even allowing `verify=False`.
        """
        if not self._decoded_access_token:
            self._decoded_access_token = self.provider.decode_token(
                self.access_token, nonce=self.auth_state.nonce, verify=verify
            )
        return self._decoded_access_token


class AuthenticationRequest:
    redirect_url: str
    auth_state: AuthenticationState

    def __init__(self, *, redirect_url, auth_state):
        self.redirect_url = redirect_url
        self.auth_state = auth_state
