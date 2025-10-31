from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_register():
    response = client.post(
        "/register",
        json={"correo": "test@test.com", "nombre": "Juan", "contraseña": "1234"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["usuario"] == "Juan"
    assert "contraseña" not in data  # nunca debe devolverse el contraseña

def test_register_existing_mail():
    response = client.post(
        "/register",
        json={"correo": "ana@gmail.com", "nombre": "Ana Perez", "contraseña": "1234"}
    )
    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "Correo ya registrado"

def test_login():
    response = client.post(
        "/login",
        json={"correo": "test@test.com", "contraseña": "1234"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Inicio de sesión exitoso"
    assert data["usuario"] == "Juan"
    

def test_login_wrong_mail():
    response = client.post(
        "/login",
        json={"correo": "tt@test.com", "contraseña": "1234"}
    )
    assert response.status_code == 404
    
def test_login_wrong_password():
    response = client.post(
        "/login",
        json={"correo": "test@test.com", "contraseña": "wrongpass"}
    )
    assert response.status_code == 401