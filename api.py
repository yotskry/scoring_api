#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import datetime
import hashlib
import json
import logging
import uuid
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer

from scoring import get_interests, get_score

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class BaseRequestMeta(type):
    def __new__(cls, name, bases, dct):
        fields = {k: v for k, v in dct.items() if isinstance(v, BaseField)}
        for field_name, field_instance in fields.items():
            field_instance.name = field_name
        dct["_fields"] = fields
        return super().__new__(cls, name, bases, dct)


class BaseField(abc.ABC):
    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable

    def validate(self, value):
        errors = []
        if self.required and value is None:
            errors.append("This field is required")
            return errors
        if value is None:
            if not self.nullable:
                errors.append("This field can not be null")
            return errors
        errors.extend(self._validate(value))
        return errors

    @abc.abstractmethod
    def _validate(self, value):
        pass


class CharField(BaseField):
    def _validate(self, value):
        errors = []
        if not isinstance(value, str):
            errors.append("Must be a string")
        elif not self.nullable and not value.strip():
            errors.append("can not be an empty string")
        return errors


class ArgumentsField(BaseField):
    def _validate(self, value):
        errors = []
        if not isinstance(value, dict):
            errors.append("Must be a dictionary")
        elif not self.nullable and value == {}:
            errors.append("can not be empty")
        return errors


class EmailField(CharField):
    def _validate(self, value):
        errors = super()._validate(value)
        if value.strip() == "":
            return errors
        if "@" not in value:
            errors.append("Invalid email format")
        return errors


class PhoneField(BaseField):
    def _validate(self, value):
        errors = []
        if isinstance(value, (str, int)):
            phone = str(value).strip()
            if len(phone) == 0:
                return errors
            if len(phone) != 11 or not phone.startswith("7"):
                errors.append("Invalid phone number format")
        else:
            errors.append("Must be a string or integer")
        return errors


class DateField(BaseField):
    def _validate(self, value):
        errors = []
        if isinstance(value, str):
            if value.strip() == "":
                return errors
            try:
                datetime.datetime.strptime(value, "%d.%m.%Y")
            except (ValueError, TypeError):
                errors.append("Invalid date format. Use DD.MM.YYYY")
        else:
            errors.append("Date should be a string")
        return errors


class BirthDayField(DateField):
    def _validate(self, value):
        errors = super()._validate(value)
        if value.strip() == "":
            return []
        if not errors:
            birth_date = datetime.datetime.strptime(value, "%d.%m.%Y").date()
            today = datetime.date.today()
            age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
            if age > 70:
                errors.append("Age must be 70 or less")
        return errors


class GenderField(BaseField):
    GENDERS = {0: "unknown", 1: "male", 2: "female"}

    def _validate(self, value):
        errors = []
        if isinstance(value, str) and value.strip() == "":
            return []
        if not isinstance(value, int):
            errors.append("Must be an integer")
        elif value not in self.GENDERS:
            errors.append("Invalid gender value")
        return errors


class ClientIDsField(BaseField):
    def _validate(self, value):
        errors = []
        if not isinstance(value, list):
            errors.append("Must be a list")
        else:
            if not value:
                errors.append("List can not be empty")
            for item in value:
                if not isinstance(item, int):
                    errors.append("All elements must be integers")
                    break
        return errors


class BaseRequest(metaclass=BaseRequestMeta):
    def __init__(self, **kwargs):
        self.errors = []
        for field_name in self._fields:
            value = kwargs.get(field_name)
            setattr(self, field_name, value)

    def validate(self):
        errors = []
        for field_name, field_instance in self._fields.items():
            value = getattr(self, field_name, None)
            field_errors = field_instance.validate(value)
            if field_errors:
                errors.extend([f"{field_name}: {error}" for error in field_errors])
        self.errors = errors
        return self.errors


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self):
        super().validate()
        valid_pairs = [
            (self.phone not in [None, ""] and self.email not in [None, ""]),
            (self.first_name not in [None, ""] and self.last_name not in [None, ""]),
            (self.gender not in [None, ""] and self.birthday not in [None, ""]),
        ]
        if not any(valid_pairs):
            self.errors.append("Required at least one pair of: phone/email, first_name/last_name, gender/birthday")
        return self.errors


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def validate(self):
        super().validate()
        if self.arguments is None:
            self.arguments = {}
        return self.errors

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request: MethodRequest):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode("utf-8")).hexdigest()
    else:
        account = str(request.account) or ""
        login = str(request.login) or ""
        digest = hashlib.sha512((account + login + SALT).encode("utf-8")).hexdigest()
    return digest == request.token


def method_handler(request, ctx, store):
    try:
        method_request = MethodRequest(**request["body"])
    except Exception as e:
        return {"error": str(e)}, INVALID_REQUEST

    # Validate request
    validation_errors = method_request.validate()
    if validation_errors:
        return {"error": validation_errors}, INVALID_REQUEST

    # Auth check
    if not check_auth(method_request):
        return {"error": "Forbidden"}, FORBIDDEN

    if method_request.method == "online_score":
        args = method_request.arguments or {}
        request_obj = OnlineScoreRequest(**args)
        errors = request_obj.validate()
        if errors:
            return {"error": errors}, INVALID_REQUEST

        valid_fields = ["phone", "email", "birthday", "gender", "first_name", "last_name"]
        ctx["has"] = [f for f in valid_fields if getattr(request_obj, f) not in [None, ""]]
        filtered_args = {k: getattr(request_obj, k) for k in valid_fields}
        response = {"score": 42 if method_request.is_admin else get_score(store, **filtered_args)}
        return response, OK

    elif method_request.method == "clients_interests":
        args = method_request.arguments or {}
        request_obj = ClientsInterestsRequest(**args)
        errors = request_obj.validate()
        if errors:
            return {"error": errors}, INVALID_REQUEST

        ctx["nclients"] = len(request_obj.client_ids)
        response = {cid: get_interests(store, cid) for cid in request_obj.client_ids}
        return response, OK
    else:
        return {"error": "Method Not Found"}, NOT_FOUND


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {"method": method_handler}
    store = None

    def get_request_id(self, headers):
        return headers.get("HTTP_X_REQUEST_ID", uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers["Content-Length"]))
            request = json.loads(data_string)
        except BaseException:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode("utf-8"))
        return


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    args = parser.parse_args()
    logging.basicConfig(
        filename=args.log,
        level=logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )
    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
