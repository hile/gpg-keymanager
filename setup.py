
from setuptools import setup, find_packages
from gpg_keymanager import __version__

setup(
    name='gpgkeymanager',
    keywords='gpg pass password store keyring management',
    description='Python utilities to manage gpg keyrings and password stores',
    author='Ilkka Tuohela',
    author_email='hile@iki.fi',
    url='https://git.tuohela.net/utils/gpg-keymanager',
    version=__version__,
    license='PSF',
    packages=find_packages(),
    python_requires='>3.6.0',
    entry_points={
        'console_scripts': [
            'gpg-keymanager=gpg_keymanager.bin.gpg_keymanager:main'
        ],
    },
    install_requires=(
        'systematic-cli>=1.3.0',
        'systematic-files>=1.3.0',
    ),
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Python Software Foundation License',
        'Operating System :: POSIX',
        'Operating System :: MacOS :: MacOS X',
        'Programming Language :: Python :: 3',
        'Topic :: System',
        'Topic :: System :: Systems Administration',
    ],
)
