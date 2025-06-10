from flask import Flask, request, jsonify
import sqlite3
import jwt
import datetime
from functools import wraps
from werkzeug.security import generate_password_hash


app = Flask(__name__)
app.config['DEBUG'] = True
SECRET_KEY = "supersecreto"

# ---------------------
#   INIT BASE DE DATOS
# ---------------------
def init_db():
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()

        # Crear tablas existentes
        cursor.execute(""" 
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                email TEXT,
                birthdate TEXT,
                status TEXT DEFAULT 'active',
                secret_question TEXT,
                secret_answer TEXT,
                role TEXT       
            )
        """)
        cursor.execute("""CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT UNIQUE
            )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS permisos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT UNIQUE
            )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS usuarios_roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER,
                rol_id INTEGER,
                UNIQUE(usuario_id, rol_id)
            )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS roles_permisos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rol_id INTEGER,
                permiso_id INTEGER,
                UNIQUE(rol_id, permiso_id)
            )""")
        # Nueva tabla para mapear rutas a permisos
        cursor.execute("""CREATE TABLE IF NOT EXISTS permisos_rutas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ruta TEXT UNIQUE,
                permiso_nombre TEXT
            )""")
    
        # Insertar usuarios si no existen
        cursor.execute("""
            INSERT INTO users (username, password, email, birthdate, secret_question, secret_answer, role) 
            SELECT 'admin', '0000', 'jaco@gmail.com', '2002-07-02', '¿Color favorito?', 'azul', 'admin'
            WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin')
        """)
        cursor.execute("""
            INSERT INTO users (username, password, role)
            SELECT 'user', 'pass','usuario'
            WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'user')
        """)

        # Insertar roles y permisos básicos
        cursor.execute("INSERT OR IGNORE INTO roles (nombre) VALUES ('admin'), ('usuario')")
        cursor.execute("""
            INSERT OR IGNORE INTO permisos (nombre) VALUES 
                ('ver_admin_data'),
                ('ver_usuarios'),
                ('gestionar_roles'),
                ('ver_roles'),
                ('crear_usuarios'),
                ('modificar_usuarios'),
                ('eliminar_usuarios')
        """)

        # Obtener IDs de usuarios
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_id = cursor.fetchone()[0]
        cursor.execute("SELECT id FROM users WHERE username = 'user'")
        user_id = cursor.fetchone()[0]

        # Obtener IDs de roles
        cursor.execute("SELECT id FROM roles WHERE nombre = 'admin'")
        rol_admin_id = cursor.fetchone()[0]
        cursor.execute("SELECT id FROM roles WHERE nombre = 'usuario'")
        rol_user_id = cursor.fetchone()[0]

        # Asignar roles a usuarios
        cursor.execute("INSERT OR IGNORE INTO usuarios_roles (usuario_id, rol_id) VALUES (?, ?)", (admin_id, rol_admin_id))
        cursor.execute("INSERT OR IGNORE INTO usuarios_roles (usuario_id, rol_id) VALUES (?, ?)", (user_id, rol_user_id))

        # Asignar todos los permisos al rol admin
        cursor.execute("SELECT id FROM permisos")
        all_permisos = cursor.fetchall()
        for permiso in all_permisos:
            permiso_id = permiso[0]
            cursor.execute("INSERT OR IGNORE INTO roles_permisos (rol_id, permiso_id) VALUES (?, ?)", (rol_admin_id, permiso_id))

        # Asignar permiso 'ver_usuarios' al rol 'usuario'
        cursor.execute("SELECT id FROM permisos WHERE nombre = 'ver_usuarios'")
        permiso_ver_usuarios_id = cursor.fetchone()[0]
        cursor.execute("INSERT OR IGNORE INTO roles_permisos (rol_id, permiso_id) VALUES (?, ?)", (rol_user_id, permiso_ver_usuarios_id))

        # Insertar mapeo de rutas a permisos
        cursor.execute("""
            INSERT OR IGNORE INTO permisos_rutas (ruta, permiso_nombre) VALUES 
                ('/users', 'ver_usuarios'),
                ('/admin/data', 'ver_admin_data'),
                ('/roles', 'ver_roles'),
                ('/user/<int:user_id>', 'modificar_usuarios'),
                ('/user/<int:user_id>/delete', 'eliminar_usuarios')
        """)

        conn.commit()

# ---------------------
#   AUTH DECORADORES
# ---------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token requerido'}), 403
        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 403
        return f(*args, **kwargs)
    return decorated

def permiso_requerido(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user_id = getattr(request, 'user_id', None)
        if not user_id:
            return jsonify({'error': 'Usuario no autenticado'}), 403

        # Obtener la ruta actual
        ruta = request.path
        # Ajustar rutas dinámicas (por ejemplo, '/user/1' -> '/user/<int:user_id>')
        if ruta.startswith('/user/') and ruta[6:].isdigit():
            ruta = '/user/<int:user_id>'
        elif ruta.startswith('/user/') and ruta.endswith('/delete'):
            ruta = '/user/<int:user_id>/delete'

        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            # Consultar el permiso asociado a la ruta
            cursor.execute("SELECT permiso_nombre FROM permisos_rutas WHERE ruta = ?", (ruta,))
            result = cursor.fetchone()
            if not result:
                return jsonify({'error': 'Ruta no configurada para permisos'}), 403
            permiso_nombre = result[0]

            # Verificar si el usuario tiene el permiso
            cursor.execute("""
                SELECT COUNT(*)
                FROM permisos p
                JOIN roles_permisos rp ON p.id = rp.permiso_id
                JOIN usuarios_roles ur ON rp.rol_id = ur.rol_id
                WHERE ur.usuario_id = ? AND p.nombre = ?
            """, (user_id, permiso_nombre))
            tiene_permiso = cursor.fetchone()[0] > 0

            if not tiene_permiso:
                return jsonify({'error': 'No tienes permiso'}), 403

        return f(*args, **kwargs)
    return wrapper

# ----------------------------
#        RUTAS CRUD USUARIOS
# ----------------------------

        #-------Iniciar sesion--------


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()

    if user:
        token = jwt.encode({
            'user_id': user[0],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
        }, SECRET_KEY, algorithm="HS256")
        return jsonify({'token': token})
    else:
        return jsonify({"message": "Credenciales inválidas"}), 401
    

    
    #-------Registrar a un nuevo usuario --------



@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    fields = ['username', 'password', 'email', 'birthdate', 'secret_question', 'secret_answer']
    if not all(field in data for field in fields):
        return jsonify({"error": "Faltan campos"}), 400

    # Hashear la contraseña
    hashed_password = generate_password_hash(data['password'])

    try:
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, password, email, birthdate, secret_question, secret_answer)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                data['username'],
                hashed_password,  # Usamos la contraseña hasheada
                data['email'],
                data['birthdate'],
                data['secret_question'],
                data['secret_answer']
            ))
            conn.commit()
        return jsonify({"message": "Usuario registrado exitosamente"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "El nombre de usuario ya existe"}), 409


@app.route('/admin/data')
@token_required
@permiso_requerido
def admin_data():
    return jsonify({"data": "Datos confidenciales solo accesibles por admin"})


        #-------Actualizar Usuario--------

@app.route('/user/<int:user_id>', methods=['PUT'])
@token_required
@permiso_requerido
def update_user(user_id):
    data = request.get_json()
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users
            SET username = ?, email = ?, birthdate = ?, secret_question = ?, secret_answer = ?
            WHERE id = ?
        """, (
            data.get('username'),
            data.get('email'),
            data.get('birthdate'),
            data.get('secret_question'),
            data.get('secret_answer'),
            user_id
        ))
        conn.commit()
    return jsonify({"message": "Usuario actualizado"})


#-------Baja logica de un Usuario--------

@app.route('/user/<int:user_id>/delete', methods=['DELETE'])
@token_required
@permiso_requerido
def delete_user(user_id):
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status = 'inactive' WHERE id = ?", (user_id,))
        conn.commit()
    return jsonify({"message": "Usuario desactivado (borrado lógico)"})


@app.route('/user/<int:user_id>', methods=['GET'])
@token_required
def get_user_by_id(user_id):
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if user:
            return jsonify({
                "id": user[0],
                "username": user[1],
                "password": user[2],
                "email": user[3],
                "birthdate": user[4],
                "status": user[5],
                "secret_question": user[6],
                "secret_answer": user[7]
            })
        else:
            return jsonify({"error": "Usuario no encontrado"}), 404



 #-------Ver/Listar usuarios--------
@app.route('/users', methods=['GET'])
@token_required
@permiso_requerido
def list_users():
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, password, email, birthdate, status, secret_question, secret_answer, role 
            FROM users
        """)
        users = cursor.fetchall()
    return jsonify([{
        "id": u[0],
        "username": u[1],
        "password": u[2],
        "email": u[3],
        "birthdate": u[4],
        "status": u[5],
        "secret_question": u[6],
        "secret_answer": u[7],
        "role": u[8]
    } for u in users])


        #-------Mostrar informacion del usuario que esta logeado--------

@app.route('/user/data', methods=['GET'])
@token_required
def user_data():
    user_id = request.user_id
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, birthdate, status FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404

        return jsonify({
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "birthdate": user[3],
            "status": user[4]
        })


# ----------------------------
#        RUTAS CRUD ROLES Y PERMISOS
# ----------------------------

         #-------Ver/Listar Roles--------

    @app.route('/roles', methods=['GET'])
    @token_required
    @permiso_requerido
    def listar_roles():
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT roles.id, roles.nombre, permisos.nombre
                FROM roles
                LEFT JOIN roles_permisos ON roles.id = roles_permisos.rol_id
                LEFT JOIN permisos ON roles_permisos.permiso_id = permisos.id
                ORDER BY roles.id
            """)
            data = cursor.fetchall()

            roles_dict = {}
            for rol_id, rol_nombre, permiso_nombre in data:
                if rol_id not in roles_dict:
                    roles_dict[rol_id] = {
                        "id": rol_id,
                        "nombre": rol_nombre,
                        "permisos": []
                    }
                if permiso_nombre:
                    roles_dict[rol_id]["permisos"].append(permiso_nombre)

            roles_lista = list(roles_dict.values())

            return jsonify(roles_lista), 200


            #-------Crear rol nuevo--------

        @app.route('/roles', methods=['POST'])
        @token_required
        @permiso_requerido
        def crear_rol():
            data = request.get_json()
            nombre = data.get('nombre')
            if not nombre:
                return jsonify({"error": "Nombre del rol requerido"}), 400
            with sqlite3.connect("database.db") as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("INSERT INTO roles (nombre) VALUES (?)", (nombre,))
                    conn.commit()
                    return jsonify({"message": "Rol creado exitosamente"}), 201
                except sqlite3.IntegrityError:
                    return jsonify({"error": "El rol ya existe"}), 409
                

        #-------Actualizar Rol--------

    @app.route('/roles/<int:rol_id>', methods=['PUT'])
    @token_required
    @permiso_requerido
    def actualizar_rol(rol_id):
        data = request.get_json()
        nuevo_nombre = data.get('nombre')
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE roles SET nombre = ? WHERE id = ?", (nuevo_nombre, rol_id))
            conn.commit()
        return jsonify({"message": "Rol actualizado"})
    

        #-------Baja logica de la tabña de roles--------

@app.route('/roles/<int:rol_id>', methods=['DELETE'])
@token_required
@permiso_requerido
def eliminar_rol(rol_id):
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()

        # Verificar que el rol existe
        cursor.execute("SELECT id FROM roles WHERE id = ?", (rol_id,))
        if not cursor.fetchone():
            return jsonify({"error": "Rol no encontrado"}), 404

        # Actualizar el estado a 'inactivo'
        cursor.execute("UPDATE roles SET status = 'inactivo' WHERE id = ?", (rol_id,))
        conn.commit()

    return jsonify({"message": "Rol desactivado correctamente"}), 200





# --------------------------
# MAIN
# --------------------------
if __name__ == '__main__':
    init_db()
    app.run()