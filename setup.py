from setuptools import setup

setup(name="card",
      author="Benoit Michau",
      author_email="michau.benoit@gmail.com",
      url="http://michau.benoit.free.fr/codes/smartcard/",
      description="A library to manipulate smartcards used in telecommunications systems (SIM, USIM)",
      long_description=open("README.txt", "r").read(),
      version="0.3",
      license="GPLv2",
      packages=["card"],
      install_requires=[
        'pyscard'
      ])
