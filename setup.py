from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='snl',
    version='1.0',
    description='a SIP library',
    long_description=long_description,
    url='https://github.com/edhinard/SIPandLove',
    platforms=['posix',],
    python_requires='>=3.5',
    classifiers=[  # Optional
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='SIP development',
    packages=['snl'],
    install_requires=['pyparsing'],
)
