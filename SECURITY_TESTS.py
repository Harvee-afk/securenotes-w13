"""Run from project root: python SECURITY_TESTS.py"""
from fastapi.testclient import TestClient
from app.main import app, db

client = TestClient(app, raise_server_exceptions=False)
def login(username, password):
    res = client.post('/login', json={'username': username, 'password': password})
    assert res.status_code == 200, res.text
    return {'Authorization': 'Bearer ' + res.json()['token']}

alice = login('alice', 'alicepass')
bob = login('bob', 'bobpass')
admin = login('admin', 'admin123')
assert client.get('/notes', headers=alice).status_code == 200
assert [n['id'] for n in client.get('/notes', headers=alice).json()] == [1]
assert client.get('/notes/2', headers=alice).status_code == 404
assert client.get('/notes/2', headers=bob).status_code == 200
assert client.get('/notes').status_code == 401
assert client.get('/notes', headers={'Authorization': 'Bearer 2'}).status_code == 401
assert client.get('/admin/users', headers=alice).status_code == 403
assert client.get('/admin/users', headers={'Authorization': 'Bearer fake'}).status_code == 401
result = client.get('/admin/users', headers=admin)
assert result.status_code == 200 and all('password' not in u for u in result.json())
assert client.post('/login', json={'username': "' OR '1'='1", 'password': 'x'}).status_code == 401
assert client.post('/login', json={'username': 'does-not-exist', 'password': 'x'}).json()['detail'] == client.post('/login', json={'username': 'alice', 'password': 'bad'}).json()['detail']
assert client.post('/register', json={'username': 'charlie', 'password': 'testpass'}).status_code == 200
charlie = login('charlie', 'testpass')
assert client.post('/notes', headers=charlie, json={'title': 'My note', 'body': 'hello'}).status_code == 200
assert len(client.get('/notes', headers=charlie).json()) == 1
assert all(u['password'].startswith('pbkdf2_sha256$') for u in db.execute('SELECT password FROM users'))
print('PASS: 17 security and functionality checks')
