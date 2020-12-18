from setuptools import setup

setup(
    name="card",
    version="0.3",
    
    packages=[
        "card"
        ],
    
    # mandatory dependency
    install_requires=[
      'pyscard'
        ],
    
    # optional dependency
    extras_require={
        'graph': ['pydot', 'graphviz']
        },
    
    author="Benoit Michau",
    author_email="michau.benoit@gmail.com",
    url="https://github.com/mitshell/card/",
    description="A library to manipulate smartcards used in telecommunications systems (SIM, USIM)",
    long_description=open("README.txt", "r").read(),
    keywords="SIM USIM UICC",
    license="GPLv2",
)
