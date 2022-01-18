from importlib.metadata import entry_points
from setuptools import setup, find_packages

setup(
    name='claripy',
    version='0.0.1',
    description='A tool made for post-exploitation analysis in python',
    author='Guilherme Ciano',
    packages= find_packages(),
    install_requires=[
        'click',
        'paramiko',
    ],
    entry_points={
        'console_scripts': [
            'claripy = claripy.__main__:main',
        ],
    }
)