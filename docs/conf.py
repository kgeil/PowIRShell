project = 'PowIRShell'
version = '0.1'
release = '0.1'
master_doc = 'README'
import sphinx_rtd_theme
html_theme = "sphinx_rtd_theme"
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
extensions = [
    ...
    'myst_parser',
    ...
]