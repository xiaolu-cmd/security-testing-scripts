import zipfile, os

BASE = os.path.dirname(os.path.abspath(__file__))
JAR_PATH = os.path.join(BASE, 'openfire-securitytest.jar')

files = [
    ('plugin.xml', 'plugin.xml'),
    ('src/main/web/index.jsp', 'web/index.jsp'),
    ('build/classes/com/securitytest/SecurityTestPlugin.class', 'com/securitytest/SecurityTestPlugin.class'),
]

with zipfile.ZipFile(JAR_PATH, 'w', zipfile.ZIP_DEFLATED) as zf:
    for src, arcname in files:
        full_path = os.path.join(BASE, src)
        zf.write(full_path, arcname)

print('JAR created successfully!')
print(f'Size: {os.path.getsize(JAR_PATH)} bytes')
print()
print('Contents:')
with zipfile.ZipFile(JAR_PATH, 'r') as zf:
    for name in zf.namelist():
        print(f'  {name}')
