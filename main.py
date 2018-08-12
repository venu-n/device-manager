from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import datetime
from functools import wraps
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "MySecretKey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///devcontrol.db"

db = SQLAlchemy(app)

class DeviceControl(db.Model):
    device_id = db.Column(db.Integer, primary_key=True)
    create_date_time = db.Column(db.String(50))
    update_date_time = db.Column(db.String(50))
    public_id = db.Column(db.String(80))
    device_name = db.Column(db.String(100))
    device_state = db.Column(db.Boolean)
    device_health = db.Column(db.String(10))
    device_type = db.Column(db.String(10))
    is_delete = db.Column(db.Boolean)
    delete_date_time = db.Column(db.String(50))
    create_user_id = db.Column(db.String(80))
    del_user_id = db.Column(db.String(80))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    is_delete = db.Column(db.Boolean)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
            pub_id = data['public_id']

        except:
            return jsonify({'message': 'Token is missing!'}), 401

        return f(current_user, pub_id, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user, pub_id):
# def get_all_users():
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id, pub_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
# @token_required
def create_user():
    # if not current_user.admin:
    #    return jsonify({'message': 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'],method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created!'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id, pub_id):
# def promote_user(public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted!'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id, pub_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8'), 'pub_id': user.public_id})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})


@app.route('/device', methods=['POST'])
@token_required
def add_device(current_user, pub_id):
    data = request.get_json()
    print(current_user)
    print(pub_id)
    new_device = DeviceControl(create_date_time=str(datetime.datetime.now()),
                               # update_date_time='',
                               public_id=str(uuid.uuid4()),
                               device_name=data['device_name'],
                               device_state=data['device_state'],
                               device_health=data['device_health'],
                               device_type=data['device_type'],
                               is_delete=0,
                               delete_date_time='',
                               create_user_id=pub_id)

    new_device_id = db.session.add(new_device)
    db.session.commit()
    """ 
    new_device_data = DeviceControl.query.filter_by(device_id=new_device_id).first()
    output = {}
    output['device_id'] = new_device_data.device_id
    output['public_id'] = new_device_data.public_id
    output['device_name'] = new_device_data.device_name
    output['device_state'] = new_device_data.device_state
    output['device_health'] = new_device_data.device_health
    output['device_type'] = new_device_data.device_type
    """

    return jsonify({"added_device": "device added successfully"})


@app.route('/device/<public_id>', methods=['DELETE'])
@token_required
def delete_device(current_user, public_id, pub_id):
    del_dev = DeviceControl.query.filter_by(public_id=public_id).first()
    # del_dev['is_delete'] = True
    # del_dev['delete_date_time'] = str(datetime.datetime.now()
    # del_dev['del_user_id'] = public_id
    db.session.delete(del_dev)
    db.session.commit()
    return jsonify({'message': 'Device deleted successfully'})


@app.route('/device/u/<public_id>', methods=['PUT'])
@token_required
def update_device_status(current_user, pub_id, public_id):
    device = DeviceControl.query.filter_by(public_id=public_id).first()
    data_state = request.get_json()
    if not device:
        return jsonify({'message': 'No device found!'})

    device.device_state = data_state['device_state']
    db.session.commit()

    return jsonify({'message': 'Device state changed!'})

    return ''


@app.route('/device/u/<public_id>', methods=['PUT'])
@token_required
def update_device_details(current_user):
    return ''


@app.route('/device', methods=['GET'])
@token_required
def get_status_all(current_user, pub_id):
    devices = DeviceControl.query.all()
    output = []
    for device in devices:
        device_data = {}
        device_data['public_id'] = device.public_id
        device_data['device_name'] = device.device_name
        device_data['device_state'] = device.device_state
        output.append(device_data)

    return jsonify({'devices': output})


@app.route('/device/<public_id>', methods=['GET'])
@token_required
def get_status_one(current_user, pub_id, public_id):
    device = DeviceControl.query.filter_by(public_id=public_id).first()
    device_data = {}
    device_data['public_id'] = device.public_id
    device_data['device_name'] = device.device_name
    device_data['device_state'] = device.device_state

    return jsonify({'devices': device_data})


@app.route('/device/details', methods=['GET'])
# @token_required
# def get_details_all(current_user, pub_id):
#    devices = DeviceControl.query.filter_by(user_id=pub_id)
def get_details_all():
    devices = DeviceControl.query.all()
    output = []
    for device in devices:
        device_data = {}
        device_data['device_id'] = device.device_id
        device_data['create_date_time'] = device.create_date_time
        device_data['public_id'] = device.public_id
        device_data['device_name'] = device.device_name
        device_data['device_state'] = device.device_state
        device_data['device_health'] = device.device_health
        device_data['device_type'] = device.device_type
        device_data['is_delete'] = device.is_delete
        device_data['delete_date_time'] = device.delete_date_time
        device_data['user_id'] = device.create_user_id
        output.append(device_data)

    return jsonify({'devices': output})


@app.route('/device/details/<public_id>', methods=['GET'])
@token_required
def get_details_one(current_user, public_id, pub_id):
    device = DeviceControl.query.filter_by(public_id=public_id, user_id=User.query.filter_by(name=current_user).first()).first()
    device_data = {}
    device_data['device_id'] = device.device_id
    device_data['create_date_time']=device.create_date_time
    device_data['public_id'] = device.public_id
    device_data['device_name'] = device.device_name
    device_data['device_state'] = device.device_state
    device_data['device_health'] = device.device_health
    device_data['device_type'] = device.device_type
    device_data['is_delete'] = device.is_delete
    device_data['delete_date_time'] = device.delete_date_time

    return jsonify({'devices': device_data})


if __name__ == "__main__":
    app.run(debug=True)
