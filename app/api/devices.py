# app/api/devices.py
# 
# Author: Indrajit Ghosh
# Created On: Mar 26, 2024
# 
from flask import jsonify
from flask_login import login_required, current_user
from flask_restful import Resource, reqparse
from app.models.models import Device
from app.extensions import db
from datetime import datetime

class AddDevice(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument(
        'device_name',
        type=str,
        required=True
        )

    @login_required
    def post(self):
        data = AddDevice.parser.parse_args()
        name = data["device_name"]

        if Device.find_by_name(name):
            return {'message': f"A device with name '{name}' already exists."}, 400

        new_device = Device(
            name=name,
            user_id=current_user.id
        )
        new_device.save_to_db()

        return  {"api_key": new_device.key}, 201