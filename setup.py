from setuptools import setup, find_packages

setup(
    name='kaba',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'requests',
        'beautifulsoup4',
        'argparse',
        'bs4',
        'datetime'
    ],
    entry_points={
        'console_scripts': [
            'kaba=kaba_scanner.__main__:main',
        ],
    },
)
