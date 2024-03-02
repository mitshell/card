from setuptools import setup

setup(
    name="card",
    version="0.3",
    
    packages=[
        "card"
    ],
    
    # mandatory dependency
    install_requires=[
        'pyscard',
        'pyserial'
    ],
    
    # optional dependency
    extras_require={
        'graph': ['pydot', 'graphviz']
    },
    
    author="Benoit Michau",
    author_email="michau.benoit@gmail.com",
    url="https://github.com/mitshell/card/",
    description="A library to manipulate smartcards used in telecommunications systems (mostly SIM, USIM)",
    long_description=open("README.md", "r").read(),
    keywords="SIM USIM UICC",
    license="GPLv2",
)
