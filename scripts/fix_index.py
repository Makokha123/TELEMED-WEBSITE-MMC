import re

with open('templates/index.html', encoding='utf-8') as f:
    content = f.read()

orig_len = len(content.splitlines())
print('Original lines:', orig_len)

# 1. Remove quick-nav div block
content = re.sub(
    r'\n<!-- Quick Navigation -->\n<div class="quick-nav d-none d-md-block">.*?</div>\n</div>\n</div>\n',
    '\n',
    content, count=1, flags=re.DOTALL
)

# 2. Update How It Works hero button to point to about page
# Find the exact text using a pattern
content = re.sub(
    r'<a href="#how-it-works" class="btn btn-hero btn-hero-outline">\s*<i class="fas fa-play-circle me-2"></i>How It Works\s*</a>',
    "<a href=\"{{ url_for('about') }}\" class=\"btn btn-hero btn-hero-outline\">\n                        <i class=\"fas fa-play-circle me-2\"></i>How It Works\n                    </a>",
    content, count=1
)

# 3. Remove About section
content = re.sub(
    r'\n<!-- About Section -->\n<section id="about".*?</section>\n',
    '\n', content, count=1, flags=re.DOTALL
)

# 4. Remove How It Works section
content = re.sub(
    r'\n<!-- How It Works Section -->\n<section id="how-it-works".*?</section>\n',
    '\n', content, count=1, flags=re.DOTALL
)

# 5. Remove Services section
content = re.sub(
    r'\n<!-- Services Section -->\n<section id="services".*?</section>\n',
    '\n', content, count=1, flags=re.DOTALL
)

# 6. Remove Doctors section
content = re.sub(
    r'\n<!-- Doctors Section -->\n<section id="doctors".*?</section>\n',
    '\n', content, count=1, flags=re.DOTALL
)

# 7. Remove Testimonials section
content = re.sub(
    r'\n<!-- Testimonials Section -->\n<section id="testimonials".*?</section>\n',
    '\n', content, count=1, flags=re.DOTALL
)

with open('templates/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

new_lines = content.splitlines()
print(f'New lines: {len(new_lines)}')

# Check remaining
patterns = ['id="about"', 'id="services"', 'id="doctors"', 'id="how-it-works"', 'id="testimonials"', 'quick-nav']
for p in patterns:
    occurrences = [(i+1) for i, line in enumerate(new_lines) if p in line]
    if occurrences:
        print(f'STILL PRESENT: {p} at lines {occurrences}')
    else:
        print(f'OK: {p} removed')
print('Done')
