"""Find unmatched triple-quoted strings in app.py"""
with open('app.py', encoding='utf-8') as f:
    lines = f.readlines()

in_triple = False
for i, line in enumerate(lines, start=1):
    stripped = line.rstrip()
    count = stripped.count('"""')
    if count % 2 == 1:
        in_triple = not in_triple
        state = 'OPEN' if in_triple else 'CLOSE'
        print(f'Line {i} ({state}): {stripped[:120]}')
    if i >= 15510:
        break

print('Final state: in_triple =', in_triple)
