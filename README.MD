## Version python  
3.9.6  

# Dependences to install  
See requirements.txt  

## Steps to run  

## 1. Create Environment  
python3 -m venv venv  

## 2. Activate venv  
source venv/bin/activate (on Linux/Unix)  
venv\Scripts\activate (on Windows)  

## 3. Install dependences  
pip install -r requirements.txt  

## 4. Run main file  
python app_vulnerable.py  

## Description  
Esta es una API desarrollada con Flask que implementa autenticación mediante JWT, control de acceso basado en roles y permisos, y operaciones CRUD sobre usuarios.  

## Funcionalidades principales:  
- Registro de usuarios  
- Login con JWT  
- Autenticación y autorización con decoradores  
- Asignación de roles y permisos  
- Rutas protegidas según los permisos  
- Borrado lógico de usuarios 
- Borrado lógico de roles 
- CRUD completo de usuarios  
- CRUD completo de roles 

## Base de datos  
Utiliza SQLite (database.db). Se crea automáticamente al ejecutar el archivo principal.  

## Endpoints importantes  
POST /register — Registrar un nuevo usuario  
POST /login — Obtener token JWT  
GET /admin/data — Solo accesible por administradores con el permiso ver_admin_data  
PUT /user/<user_id> — Actualizar datos del usuario  
DELETE /user/<user_id> — Borrado lógico  
GET /user/<user_id> — Obtener usuario por ID  
GET /user?username=<username> — Obtener usuario por nombre  
GET /users-with-permissions — Obtener usuarios junto con roles y permisos  
GET /roles — Lista todos los roles existentes con sus permisos asociados. Requiere token JWT válido.
POST /roles — Crea un nuevo rol. Recibe JSON con campo nombre. Requiere token JWT válido.
PUT /roles/int:rol_id — Actualiza el nombre de un rol existente identificado por rol_id. Requiere token JWT válido.
DELETE /roles/int:rol_id — Elimina un rol identificado por rol_id. Requiere token JWT válido.

## Notas  
Usuario por defecto: admin / 1234  
Rol por defecto: admin con permiso ver_admin_data  
El token JWT expira en 5 minutos  

## Seguridad  
Este proyecto es vulnerable intencionalmente y puede usarse con fines educativos para probar mecanismos de autenticación/autorización, manejo de sesiones y estructura de roles.  
