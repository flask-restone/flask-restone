# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import os
import sys
sys.path.append(os.path.abspath("."))

# extensions = ['helloworld']
sys.path.append(os.path.abspath('../../src'))
sys.path.append(os.path.abspath('_themes'))


project = 'Flask-Restone'
copyright = '2023, Arry Lee'
author = 'arry_lee'
release = '0.1.0'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.todo',
    'sphinx.ext.imgmath',
]

autodoc_member_order = 'bysource'

templates_path = ['_templates']
exclude_patterns = []

html_theme_path = ['_themes']
html_theme = 'flask'
index_logo = 'logo.png'

language = 'EN'

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

# html_theme = 'alabaster'
html_static_path = ['_static']
