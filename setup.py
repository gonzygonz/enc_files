from setuptools import setup, find_packages

setup(name='enc_files',
      packages=['enc_files'],  # find_packages(),
      version='1.0',
      description='Encrypt your files',
      author='LW',
      license='LICENSE',
      install_requires=[
          'Crypto', 'cryptoshop', 'pycryptodome', 'pytest'
      ], )
