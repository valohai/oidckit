import json
from typing import Optional

import requests

from oidckit.excs import OIDCError, RemoteError
from oidckit.crypto import decode_jws, get_key_from_keyset_json
from oidckit.objects import AuthenticationState, AuthenticationResult


class OIDCProviderConfiguration:
    op_authorization_endpoint: str
    op_jwks_endpoint: str
    op_token_endpoint: str
    op_user_endpoint: str
    rp_client_id: str
    rp_client_secret: str
    rp_scopes: str = "openid email"
    rp_sign_algo: str = "HS256"


class OIDCProvider:
    config: OIDCProviderConfiguration
    nonce_size: int = 32
    state_size: int = 32

    _session = None
    _jwks_data = None

    @property
    def session(self):
        if not self._session:
            self._session = requests.Session()
        return self._session

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

    def build_authentication_request_params(
        self, *, redirect_uri: str, state: str, request=None
    ) -> dict:
        return {
            "client_id": self.config.rp_client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": self.config.rp_scopes,
            "state": state,
        }

    def build_token_request_payload(
        self, *, code: str, auth_state: AuthenticationState
    ):
        return {
            "client_id": self.config.rp_client_id,
            "client_secret": self.config.rp_client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": auth_state.redirect_uri,
        }

    def retrieve_token(self, payload: dict) -> dict:
        response = self.session.post(self.config.op_token_endpoint, data=payload)
        RemoteError.raise_from_status(response)
        return response.json()

    def retrieve_token_key(self, token) -> dict:
        if self.config.rp_sign_algo.startswith("RS"):
            if self.config.op_jwks_endpoint:
                if not self._jwks_data:
                    response = self.session.get(self.config.op_jwks_endpoint)
                    RemoteError.raise_from_status(response)
                    self._jwks_data = response.json()
                return get_key_from_keyset_json(
                    keyset_json=self._jwks_data, token=token
                )
        raise NotImplementedError("No idea how to get token key – subclass, please")

    def get_payload_data(self, token: bytes, key: dict, verify: bool = True):
        return decode_jws(
            payload=token,
            key=key,
            expected_algorithm=self.config.rp_sign_algo,
            verify=verify,
        )

    def decode_token(
        self, token: str, nonce: Optional[str] = None, verify: bool = True
    ) -> dict:
        token = str(token).encode("utf-8")
        key = self.retrieve_token_key(token)
        payload_data = self.get_payload_data(token, key, verify=verify)
        payload = json.loads(payload_data)
        if nonce and verify:
            token_nonce = payload.get("nonce")
            if nonce != token_nonce:
                raise OIDCError(
                    f"Token nonce mismatch – expected {nonce}, got {token_nonce}"
                )
        return payload

    def retrieve_user_info(self, auth_result: AuthenticationResult) -> Optional[dict]:
        if not self.config.op_user_endpoint:
            return None
        user_response = self.session.get(
            self.config.op_user_endpoint,
            headers={"Authorization": f"Bearer {auth_result.access_token}"},
        )
        user_response.raise_for_status()
        return user_response.json()
