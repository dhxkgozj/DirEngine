try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name    = 'DirEngine',
    version = '1.0.0',
    packages = ['DirEngine','DirEngine.Header','DirEngine.Header.Archinfo','DirEngine.error','DirEngine.Functions'],
    author = 'egoist',
    author_email = 'kdw8726@naver.com',
    url = 'http://www.bafegoist.com',
    description = 'this',
    )