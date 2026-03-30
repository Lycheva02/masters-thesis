from __future__ import annotations

import re

URL_ACTION_MAP = [
    (r"/index\.jsp$", "HOME"),
    (r"/publico/registro\.jsp$", "REGISTER"),
    (r"/publico/autenticar\.jsp$", "AUTHENTICATE"),
    (r"/publico/entrar\.jsp$", "LOGIN_RESULT"),
    (r"/miembros/editar\.jsp$", "EDIT_PROFILE"),
    (r"/publico/anadir\.jsp$", "ADD_TO_CART"),
    (r"/publico/pagar\.jsp$", "CHECKOUT"),
    (r"/publico/vaciar\.jsp$", "CLEAR_CART"),
    (r"/publico/carrito\.jsp$", "VIEW_CART"),
    (r"/publico/caracteristicas\.jsp$", "VIEW_PRODUCT"),
    (r"/publico/miembros\.jsp$", "VIEW_MEMBERS"),
    (r"/publico/productos\.jsp$", "VIEW_PRODUCTS"),
    (r"/miembros/index\.jsp$", "MEMBER_HOME"),
    (r"/miembros/fotos\.jsp$", "VIEW_PHOTOS"),
    (r"/miembros/salir\.jsp$", "LOGOUT"),
]

STATIC_EXTENSIONS = (".css", ".jpg", ".jpeg", ".gif", ".png", ".ico")


def abstract_path(path: str) -> str:
    for pattern, action in URL_ACTION_MAP:
        if re.search(pattern, path):
            return action
    if path.endswith(STATIC_EXTENSIONS):
        return "STATIC"
    return "OTHER"


def make_action_token(method: str, path: str) -> str:
    return f"{method}_{abstract_path(path)}"
