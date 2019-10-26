import secrets
import string

from josepy import JWK, JWS, Header

from oidckit.excs import OIDCError


def decode_jws(
    payload: bytes, key: dict, expected_algorithm: str, verify: bool = True
) -> dict:
    jws = JWS.from_compact(payload)
    if verify:
        try:
            alg = jws.signature.combined.alg.name
        except KeyError as exc:
            raise OIDCError("No alg value found in header") from exc

        if alg != expected_algorithm:
            raise OIDCError(
                f"Algorithm mismatch: offered {alg} is not expected {expected_algorithm}"
            )

        jwk = JWK.from_json(key)
        if not jws.verify(jwk):
            raise OIDCError("JWS token verification failed.")

    return jws.payload


def get_key_from_keyset_json(keyset_json: dict, token: bytes) -> dict:
    jws = JWS.from_compact(token)
    header = Header.json_loads(jws.signature.protected)
    expected_kid = str(header.kid)
    expected_alg = str(header.alg)

    for jwk in keyset_json["keys"]:
        if jwk["kid"] != expected_kid:
            continue
        jwk_alg = jwk.get("alg")
        if jwk_alg and jwk_alg != expected_alg:
            raise OIDCError(
                f"kid {header.kid} has alg {jwk_alg}, was expecting {header.alg}"
            )
        return jwk
    raise OIDCError(f"Keyset has no matching key for kid {expected_kid}.")


def get_random_string(
    length=12,
    keyspace=(string.ascii_lowercase + string.ascii_uppercase + string.digits),
):
    return "".join(secrets.choice(keyspace) for i in range(length))
