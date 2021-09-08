import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="cheat-engine-py-56kyle",
    version="0.0.1",
    author="Kyle Oliver",
    author_email="56kyleoliver@gmail.com",
    description="A package for automating some of the processes of cheat engine in python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/56kyle/cheat_engine_py",
    project_urls={
        "Bug Tracker": "https://github.com/56kyle/cheat_engine_py/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
)
