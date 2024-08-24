from setuptools import setup

setup(
    name='kaba',
    version='0.1',
    py_modules=['kaba_scanner'],
    install_requires=[
        'requests',
        'beautifulsoup4',
        'argparse',
        'subprocess',
        'multiprocessing',
        'bs4',
        'datetime',
        'pycopy-urllib.parse',
        'logging',
    ],
    entry_points='''
        [console_scripts]
        kaba=kaba_scanner:main
    ''',
)
