# Zelos CrasHD Plugin

A plugin for [Zelos](https://github.com/zeropointdynamics/zelos) to enhance crash triaging by performing dataflow & root cause analysis.

## Optional Prerequisites

This plugin has an optional dependency on the [graphviz](https://pypi.org/project/graphviz/) package to render control flow graphs to png. The graphviz python package can be installed normally via `pip install graphviz`, but will also require [Graphviz](https://www.graphviz.org/) itself to be installed locally as well. Instructions for installing Graphviz locally can be found [here](https://graphviz.org/download/). 

If you do not wish to install the graphviz package or Graphviz, you can safely ignore this optional dependency and zelos-crashd will still work as intended, but control flow graphs will not be rendered to png.

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

[CrasHD Examples](https://github.com/zeropointdynamics/examples-crashd) is a collection of reproducible crashes that can be used with this plugin.

## Usage

The following snippets use the example from [examples-crashd/afl_training/vulnerable.c](https://github.com/zeropointdynamics/examples-crashd/tree/master/afl_training)

After compiling the above example (`vulnerable.c`) you can emulate the binary using zelos:
```console
$ zelos vulnerable < inputs/crashing_input
```

To gain a more information on the crashing program, use the `--taint` and `--taint_output` flags in order to keep track of dataflow leading from the crash. When the `--taint` flag is used, Zelos will calculate the dataflow and taint information related to the crash. `--taint_output terminal` is used to specify that the output of `--taint` will be to stdout.
```console
$ zelos --taint --taint_output terminal vulnerable < inputs/crashing_input
```
