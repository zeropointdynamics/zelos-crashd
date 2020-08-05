# Zelos CrasHD Plugin

A plugin for [Zelos](https://github.com/zeropointdynamics/zelos) to enhance crash triaging by performing dataflow & root cause analysis.

## Prerequisites

This plugin depends on [Graphviz](https://graphviz.org/) to render control flow graphs. Instructions for installing Graphviz locally can be found [here](https://graphviz.org/download/). 

## Installation

Install from pypi
```console
$ pip install zelos-crashd
```

Or install directly from the repo
```console
$ git clone https://github.com/zeropointdynamics/zelos-crashd.git
$ cd zelos-crashd
$ pip install .
```

Alternatively, install an _editable_ version for development
```console
$ git clone https://github.com/zeropointdynamics/zelos-crashd.git
$ cd zelos-crashd
$ pip install -e '.[dev]'
```

## Related Resources

[CrasHD Visualizer](https://github.com/zeropointdynamics/vscode-crashd) is a VS Code extension for visualizing the results & output of this plugin that features:
- Contextual source code highlighting
- Interactive graph of data flow
- Additional context & runtime information

