import setuptools

with open('Readme.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

with open("requirements.txt", encoding='utf-8') as f:
    requirements = [x.strip() for x in f]

setuptools.setup(
    name='pe_parser',
    version='0.1',
    author='Konstantin Kozlov',
    description='exe parser',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)
