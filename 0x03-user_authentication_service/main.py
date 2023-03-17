#!/usr/bin/env python3
"""This file contains end-to-end
integration tests for the user auth service
"""
import requests

url = 'http://localhost:5000/'


def register_user(email: str, password: str) -> None:
    """The register_user"""
    url_path = url + 'users'
    data = {
        'email': email,
        'password': password
    }
    resp = requests.post(url_path, data=data)
    resp_json = resp.json()
    expected = {'email': "{}".format(email),
                'message': 'user created'}
    expected_fail = {"message": "email already registered"}
    if resp.status_code == 200:
        assert resp_json == expected
    else:
        assert resp.status_code == 400
        assert resp_json == expected_fail


def log_in_wrong_password(email: str, password: str) -> None:
    """This function tests a login
    with the wrong password"""
    url_path = url + 'sessions'
    data = {
        'email': email,
        'password': password
    }
    resp = requests.post(url_path, data=data)
    assert resp.status_code == 401


def profile_unlogged() -> None:
    """This function tests an unlogged profile"""
    url_path = url + 'profile'
    resp = requests.get(url_path)
    assert resp.status_code == 403


def log_in(email: str, password: str) -> str:
    """This function tests user login"""
    url_path = url + 'sessions'
    data = {
        'email': email,
        'password': password
    }
    resp = requests.post(url_path, data=data)
    resp_json = resp.json()
    assert resp_json == ({"email": "{}".format(email), "message": "logged in"})
    return resp.cookies.get('session_id')


def profile_logged(session_id: str) -> None:
    """This function tests getting logged in user's profile"""
    url_path = url + 'profile'
    cookies = {'session_id': session_id}
    resp = requests.get(url_path, cookies=cookies)
    assert resp.status_code == 200


def log_out(session_id: str) -> None:
    """This function tests logging out a user's session"""
    url_path = url + 'sessions'
    cookies = {'session_id': session_id}
    resp = requests.delete(url_path, cookies=cookies)
    if resp.status_code == 302:
        assert resp.url == url
    elif resp.status_code != 403:
        assert resp.status_code == 200


def reset_password_token(email: str) -> str:
    """This function returns the result of the reset/-password_token"""
    url_path = url + 'reset_password'
    data = {
        "email": email
    }
    resp = requests.post(url_path, data=data).json()
    return resp.get('reset_token')


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """This function tests the update password route"""
    url_path = url + 'reset_password'
    data = {
        'email': email,
        'reset_token': reset_token,
        'new_password': new_password
    }
    resp = requests.put(url_path, data=data)
    expected = {"email": "{}".format(email), "message": "Password updated"}
    if resp.status_code == 200:
        assert resp.json() == expected
    else:
        assert resp.status_code == 403


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
