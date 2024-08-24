from setuptools import setup

setup(
    name='kaba',
    version='0.1',
    py_modules=['kaba'],
    install_requires=[
        'requests',
        'beautifulsoup4',
        'argparse',
        'datetime'
    ],
    entry_points={
        'console_scripts': [
            'kaba=kaba:main', 
        ],
    },
)
