with open('app.py', 'rb') as f:
    content = f.read()
# The broken docstring line
old = b'    """Video call page for appointments (legacy fallback)"'
new = b'    """Video call page for appointments (legacy fallback)"""'
if old in content:
    print('Found broken docstring, fixing...')
    content = content.replace(old, new, 1)
    with open('app.py', 'wb') as f:
        f.write(content)
    print('Fixed successfully.')
else:
    print('Pattern not found!')
    idx = content.find(b'legacy fallback')
    if idx >= 0:
        print('Context:', repr(content[idx-10:idx+60]))
