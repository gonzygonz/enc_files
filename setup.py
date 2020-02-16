from setuptools import setup, find_packages

setup(name='EncFiles',
      packages=find_packages(),
      version='1.0',
      description='Encrypt your files',
      author='LW',
      install_requires=[
          'Crypto', 'cryptoshop', 'pycryptodome'
      ], )
