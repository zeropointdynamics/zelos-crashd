from setuptools import find_packages, setup

PACKAGES = find_packages(where="src")

setup(
    name="zelos_crashd",
    # install_requires=["zelos", "graphviz"],
    install_requires=[],
    include_package_data=True,
    packages=PACKAGES,
    package_dir={"": "src"},
    entry_points={
        "zelos.plugins": [
            "asan=crashd.asan",
            "dataflow=crashd.taint",
            "ida=crashd.static_analysis",
        ],
    },
)
